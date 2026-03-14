const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Resend } = require("resend");
const { S3Client, GetObjectCommand, HeadBucketCommand, HeadObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { Pool } = require("pg");

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const app = express();
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const PORT = Number(process.env.PORT || 3000);
const CLIENT_URL = process.env.CLIENT_URL || "";
const BACKEND_PUBLIC_URL = (process.env.BACKEND_PUBLIC_URL || "").replace(/\/$/, "");
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "";
const PRODUCT_NAME = process.env.PRODUCT_NAME || "WAV Vault Vol. 1";
const PRODUCT_PRICE = Number(process.env.PRODUCT_PRICE || 49.99);
const DOWNLOAD_SESSION_MINUTES = Number(process.env.DOWNLOAD_SESSION_MINUTES || 15);
const R2_URL_EXPIRES_SECONDS = Number(process.env.R2_URL_EXPIRES_SECONDS || 300);
const ORDER_ACCESS_LINK_TTL_DAYS = Number(process.env.ORDER_ACCESS_LINK_TTL_DAYS || 0); // 0 = sem expiração

const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID || "";
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || "";
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || "";
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || "";
const R2_OBJECT_KEY = process.env.R2_OBJECT_KEY || "";
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || "";

app.use(cors({ origin: CLIENT_URL ? [CLIENT_URL] : true }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const dataDir = path.join(__dirname, "data");
const ordersFile = path.join(dataDir, "orders.json");

function ensureStorage() {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  if (!fs.existsSync(ordersFile)) fs.writeFileSync(ordersFile, "{}", "utf-8");
}

function readOrders() {
  ensureStorage();
  const raw = fs.readFileSync(ordersFile, "utf-8");
  return raw ? JSON.parse(raw) : {};
}

function writeOrders(orders) {
  ensureStorage();
  fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2), "utf-8");
}

function saveOrder(order) {
  const orders = readOrders();
  orders[order.id] = order;
  writeOrders(orders);
  return order;
}

function getOrder(orderId) {
  const orders = readOrders();
  return orders[orderId] || null;
}

function findOrderByAccessToken(accessToken) {
  const orders = readOrders();
  return Object.values(orders).find((o) => o.accessToken === accessToken) || null;
}

function findOrderByPaymentId(paymentId) {
  const orders = readOrders();
  return Object.values(orders).find((o) => String(o.paymentId || "") === String(paymentId)) || null;
}

function findOrderByDownloadSession(sessionToken) {
  const orders = readOrders();
  return (
    Object.values(orders).find((o) => {
      if (!o.downloadSession) return false;
      if (o.downloadSession.token !== sessionToken) return false;
      if (o.downloadSession.usedAt) return false;
      return new Date(o.downloadSession.expiresAt).getTime() > Date.now();
    }) || null
  );
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateOrderId() {
  return `order_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
}

function generateToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

function buildAccessLink(accessToken) {
  return `${BACKEND_PUBLIC_URL}/access/${accessToken}`;
}

function buildDownloadLink(sessionToken) {
  return `${BACKEND_PUBLIC_URL}/download/${sessionToken}`;
}

function shouldUseNotificationUrl() {
  return Boolean(BACKEND_PUBLIC_URL && /^https:\/\//i.test(BACKEND_PUBLIC_URL));
}

function isOrderAccessExpired(order) {
  if (!ORDER_ACCESS_LINK_TTL_DAYS) return false;
  if (!order.paidAt) return true;
  const expiresAt = new Date(new Date(order.paidAt).getTime() + ORDER_ACCESS_LINK_TTL_DAYS * 24 * 60 * 60 * 1000);
  return expiresAt.getTime() < Date.now();
}

function createDownloadSession(order) {
  order.downloadSession = {
    token: generateToken(24),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + DOWNLOAD_SESSION_MINUTES * 60 * 1000).toISOString(),
    usedAt: null,
  };
  saveOrder(order);
  return order.downloadSession;
}

function getR2Client() {
  if (!R2_ACCOUNT_ID || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) {
    throw new Error("Credenciais R2 não configuradas.");
  }

  return new S3Client({
    region: "auto",
    endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: R2_ACCESS_KEY_ID,
      secretAccessKey: R2_SECRET_ACCESS_KEY,
    },
  });
}

async function generateR2DownloadUrl() {
  if (!R2_BUCKET_NAME || !R2_OBJECT_KEY) {
    throw new Error("R2_BUCKET_NAME ou R2_OBJECT_KEY não configurado.");
  }

  const r2 = getR2Client();
  const command = new GetObjectCommand({
    Bucket: R2_BUCKET_NAME,
    Key: R2_OBJECT_KEY,
    ResponseContentDisposition: `attachment; filename="${path.basename(R2_OBJECT_KEY)}"`,
  });

  return await getSignedUrl(r2, command, { expiresIn: R2_URL_EXPIRES_SECONDS });
}

async function sendApprovedEmail(order) {
  if (!resend || !EMAIL_FROM) {
    console.warn("Resend/EMAIL_FROM não configurado. Email não enviado.");
    return false;
  }

  const accessLink = buildAccessLink(order.accessToken);

  await resend.emails.send({
    from: EMAIL_FROM,
    to: [order.email],
    subject: `Seu acesso ao ${PRODUCT_NAME}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;line-height:1.6;color:#111827;">
        <h2>Pagamento aprovado 🎉</h2>
        <p>Seu pedido do <strong>${PRODUCT_NAME}</strong> foi aprovado.</p>
        <p>Guarde este email. Sempre que precisar baixar novamente, use o botão abaixo e confirme o email usado na compra.</p>
        <p>
          <a href="${accessLink}" style="display:inline-block;background:#111827;color:#ffffff;padding:12px 18px;border-radius:10px;text-decoration:none;font-weight:700;">
            Acessar meu download
          </a>
        </p>
        <p>Se preferir, copie o link:</p>
        <p>${accessLink}</p>
      </div>
    `,
  });

  return true;
}

function renderAccessPage({ accessToken, error = "", success = "", email = "", showDownloadButton = false, downloadUrl = "" }) {
  const errorHtml = error ? `<p style="color:#f87171;margin-top:14px;">${error}</p>` : "";
  const successHtml = success ? `<p style="color:#4ade80;margin-top:14px;">${success}</p>` : "";
  const downloadButton = showDownloadButton
    ? `<a href="${downloadUrl}" style="display:block;margin-top:16px;width:100%;box-sizing:border-box;padding:14px;text-align:center;text-decoration:none;font-weight:700;border-radius:12px;background:#22c55e;color:#052e16;">Baixar arquivo agora</a>`
    : "";

  return `<!doctype html>
  <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Acessar download</title>
      <style>
        body { margin:0; font-family:Arial,sans-serif; background:#0f172a; color:#e2e8f0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
        .card { width:100%; max-width:520px; background:#111827; border:1px solid rgba(255,255,255,.08); border-radius:18px; padding:28px; box-shadow:0 20px 60px rgba(0,0,0,.35); }
        h1 { margin-top:0; font-size:28px; line-height:1.2; }
        p { color:#cbd5e1; line-height:1.5; }
        label { display:block; margin:20px 0 8px; font-weight:600; }
        input { width:100%; box-sizing:border-box; padding:14px; border-radius:12px; border:1px solid #334155; background:#0b1220; color:#e2e8f0; font-size:15px; }
        button { margin-top:18px; width:100%; border:none; border-radius:12px; padding:14px; font-size:16px; font-weight:700; cursor:pointer; background:#38bdf8; color:#082f49; }
        .muted { font-size:13px; color:#94a3b8; margin-top:14px; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Baixar ${PRODUCT_NAME}</h1>
        <p>Digite o email usado na compra para liberar seu download.</p>
        <form method="POST" action="/access/${accessToken}">
          <label for="email">Email da compra</label>
          <input id="email" name="email" type="email" required placeholder="voce@exemplo.com" value="${email}" />
          <button type="submit">Liberar download</button>
        </form>
        ${errorHtml}
        ${successHtml}
        ${downloadButton}
        <p class="muted">O link do email continua útil. O arquivo real só é liberado temporariamente após a confirmação do email.</p>
      </div>
    </body>
  </html>`;
}

function safeCompare(a, b) {
  const aBuf = Buffer.from(String(a || ""));
  const bBuf = Buffer.from(String(b || ""));
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function verifyWebhookSignature(req) {
  if (!MP_WEBHOOK_SECRET) return true;
  const signatureHeader = req.headers["x-signature"];
  if (!signatureHeader) return false;
  return String(signatureHeader).includes(MP_WEBHOOK_SECRET);
}

async function fetchMercadoPagoPayment(paymentId) {
  const response = await axios.get(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
    headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}` },
  });
  return response.data;
}

async function markOrderApproved(order, payment) {
  if (order.status === "approved") return order;

  order.status = "approved";
  order.paidAt = new Date().toISOString();
  order.paymentId = payment.id || order.paymentId;
  order.paymentStatus = payment.status || order.paymentStatus;
  saveOrder(order);

  try {
    const sent = await sendApprovedEmail(order);
    if (sent) {
      order.emailSent = true;
      order.emailSentAt = new Date().toISOString();
      saveOrder(order);
    }
  } catch (emailError) {
    console.error("Erro ao enviar email:", emailError.response?.data || emailError.message);
  }

  return order;
}

app.get("/", async (req, res) => {
  res.json({ ok: true, message: "Backend Mercado Pago + R2 rodando." });
});

app.get("/health", async (req, res) => {
  const health = {
    ok: true,
    time: new Date().toISOString(),
    checks: {
      backendPublicUrl: shouldUseNotificationUrl(),
      resend: Boolean(process.env.RESEND_API_KEY && EMAIL_FROM),
      mercadoPago: Boolean(MP_ACCESS_TOKEN),
      r2: false,
    },
  };

  try {
    const r2 = getR2Client();
    await r2.send(new HeadBucketCommand({ Bucket: R2_BUCKET_NAME }));
    await r2.send(new HeadObjectCommand({ Bucket: R2_BUCKET_NAME, Key: R2_OBJECT_KEY }));
    health.checks.r2 = true;
  } catch (error) {
    health.ok = false;
    health.r2Error = error.message;
  }

  if (!health.checks.mercadoPago) health.ok = false;
  if (!health.checks.resend) health.ok = false;

  res.status(health.ok ? 200 : 500).json(health);
});

app.post("/create-pix", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const confirmEmail = normalizeEmail(req.body.confirmEmail);

    if (!email || !confirmEmail) {
      return res.status(400).json({ error: "Preencha os dois emails." });
    }

    if (email !== confirmEmail) {
      return res.status(400).json({ error: "Os emails não coincidem." });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Email inválido." });
    }

    if (!MP_ACCESS_TOKEN) {
      return res.status(500).json({ error: "MP_ACCESS_TOKEN não configurado." });
    }

    const orderId = generateOrderId();
    const accessToken = generateToken(24);

    const order = {
      id: orderId,
      email,
      status: "pending",
      paymentStatus: null,
      paymentId: null,
      accessToken,
      createdAt: new Date().toISOString(),
      paidAt: null,
      emailSent: false,
      emailSentAt: null,
      downloadSession: null,
      lastMpCheckAt: null,
      amount: PRODUCT_PRICE,
      productName: PRODUCT_NAME,
    };

    saveOrder(order);

    const paymentData = {
      transaction_amount: PRODUCT_PRICE,
      description: PRODUCT_NAME,
      payment_method_id: "pix",
      payer: { email },
      external_reference: orderId,
    };

    if (shouldUseNotificationUrl()) {
      paymentData.notification_url = `${BACKEND_PUBLIC_URL}/webhook`;
    }

    const response = await axios.post("https://api.mercadopago.com/v1/payments", paymentData, {
      headers: {
        Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
        "Content-Type": "application/json",
        "X-Idempotency-Key": orderId,
      },
    });

    const payment = response.data;
    order.paymentId = payment.id;
    order.paymentStatus = payment.status || null;
    saveOrder(order);

    return res.json({
      success: true,
      orderId,
      paymentId: payment.id,
      status: payment.status,
      pixCode: payment.point_of_interaction?.transaction_data?.qr_code || null,
      qrCodeBase64: payment.point_of_interaction?.transaction_data?.qr_code_base64 || null,
    });
  } catch (error) {
    console.error("Erro ao criar Pix:", error.response?.data || error.message);
    return res.status(500).json({
      error: "Erro ao criar pagamento Pix.",
      details: error.response?.data || error.message,
    });
  }
});

app.get("/payment-status/:orderId", async (req, res) => {
  try {
    const order = getOrder(req.params.orderId);
    if (!order) {
      return res.status(404).json({ error: "Pedido não encontrado." });
    }

    if (order.paymentId && order.status !== "approved") {
      try {
        const payment = await fetchMercadoPagoPayment(order.paymentId);
        order.lastMpCheckAt = new Date().toISOString();
        order.paymentStatus = payment.status || order.paymentStatus;
        saveOrder(order);

        if (payment.status === "approved") {
          await markOrderApproved(order, payment);
        }
      } catch (mpError) {
        console.error("Falha ao reconciliar status do pagamento:", mpError.response?.data || mpError.message);
      }
    }

    const freshOrder = getOrder(req.params.orderId);

    return res.json({
      orderId: freshOrder.id,
      status: freshOrder.status,
      paymentStatus: freshOrder.paymentStatus,
      emailSent: freshOrder.emailSent,
      accessUrl: freshOrder.status === "approved" ? buildAccessLink(freshOrder.accessToken) : null,
    });
  } catch (error) {
    console.error("Erro em /payment-status:", error.message);
    return res.status(500).json({ error: "Erro ao consultar status do pedido." });
  }
});

app.post("/webhook", async (req, res) => {
  try {
    if (!verifyWebhookSignature(req)) {
      console.warn("Webhook rejeitado por assinatura inválida.");
      return res.status(200).send("ok");
    }

    const body = req.body || {};
    const paymentId = body?.data?.id || body?.resource?.split("/").pop() || req.query["data.id"] || req.query.id;

    if (!paymentId) {
      return res.status(200).send("ok");
    }

    const payment = await fetchMercadoPagoPayment(paymentId);
    const orderId = payment.external_reference;
    if (!orderId) {
      return res.status(200).send("ok");
    }

    const order = getOrder(orderId) || findOrderByPaymentId(paymentId);
    if (!order) {
      return res.status(200).send("ok");
    }

    order.paymentId = payment.id || order.paymentId;
    order.paymentStatus = payment.status || order.paymentStatus;
    order.lastMpCheckAt = new Date().toISOString();
    saveOrder(order);

    if (payment.status === "approved") {
      await markOrderApproved(order, payment);
    }

    return res.status(200).send("ok");
  } catch (error) {
    console.error("Erro no webhook:", error.response?.data || error.message);
    return res.status(200).send("ok");
  }
});

app.get("/access/:accessToken", (req, res) => {
  const order = findOrderByAccessToken(req.params.accessToken);

  if (!order || order.status !== "approved") {
    return res.status(403).send("Link inválido ou pagamento não aprovado.");
  }

  if (isOrderAccessExpired(order)) {
    return res.status(403).send("O período deste link expirou. Entre em contato com o suporte.");
  }

  return res.status(200).send(renderAccessPage({ accessToken: req.params.accessToken }));
});

app.post("/access/:accessToken", (req, res) => {
  const order = findOrderByAccessToken(req.params.accessToken);
  const typedEmail = normalizeEmail(req.body.email);

  if (!order || order.status !== "approved") {
    return res.status(403).send("Link inválido ou pagamento não aprovado.");
  }

  if (isOrderAccessExpired(order)) {
    return res.status(403).send("O período deste link expirou. Entre em contato com o suporte.");
  }

  if (!typedEmail || !isValidEmail(typedEmail)) {
    return res.status(400).send(renderAccessPage({
      accessToken: req.params.accessToken,
      email: typedEmail,
      error: "Digite um email válido.",
    }));
  }

  if (!safeCompare(typedEmail, normalizeEmail(order.email))) {
    return res.status(401).send(renderAccessPage({
      accessToken: req.params.accessToken,
      email: typedEmail,
      error: "Esse email não corresponde ao email usado na compra.",
    }));
  }

  const session = createDownloadSession(order);
  const downloadUrl = buildDownloadLink(session.token);

  return res.status(200).send(renderAccessPage({
    accessToken: req.params.accessToken,
    email: typedEmail,
    success: `Email confirmado. O botão abaixo fica válido por ${DOWNLOAD_SESSION_MINUTES} minutos.`,
    showDownloadButton: true,
    downloadUrl,
  }));
});

app.get("/download/:sessionToken", async (req, res) => {
  try {
    const order = findOrderByDownloadSession(req.params.sessionToken);

    if (!order || order.status !== "approved") {
      return res.status(403).send("Sessão de download inválida ou expirada.");
    }

    const signedUrl = await generateR2DownloadUrl();
    order.downloadSession.usedAt = new Date().toISOString();
    saveOrder(order);

    return res.redirect(signedUrl);
  } catch (error) {
    console.error("Erro ao liberar download do R2:", error.message);
    return res.status(500).send("Erro ao liberar download.");
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
