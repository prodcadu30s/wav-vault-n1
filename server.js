const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const axios = require("axios");
const crypto = require("crypto");
const { Resend } = require("resend");
const {
  S3Client,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { Pool } = require("pg");

dotenv.config();

const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-signature", "x-request-id"],
  })
);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

const PORT = Number(process.env.PORT || 3000);
const CLIENT_URL = process.env.CLIENT_URL || "";
const BACKEND_PUBLIC_URL = (process.env.BACKEND_PUBLIC_URL || "").replace(/\/$/, "");
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || "";
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "";
const PRODUCT_NAME = process.env.PRODUCT_NAME || "WAV Vault Vol. 1";
const PRODUCT_PRICE = Number(process.env.PRODUCT_PRICE || 49.99);
const DOWNLOAD_SESSION_MINUTES = Number(process.env.DOWNLOAD_SESSION_MINUTES || 15);
const R2_URL_EXPIRES_SECONDS = Number(process.env.R2_URL_EXPIRES_SECONDS || 300);
const ORDER_ACCESS_LINK_TTL_DAYS = Number(process.env.ORDER_ACCESS_LINK_TTL_DAYS || 0);
const MAX_DOWNLOADS_PER_ORDER = Number(process.env.MAX_DOWNLOADS_PER_ORDER || 5);
const MAX_ACCESS_ATTEMPTS_PER_WINDOW = Number(process.env.MAX_ACCESS_ATTEMPTS_PER_WINDOW || 5);
const ACCESS_ATTEMPT_WINDOW_MINUTES = Number(process.env.ACCESS_ATTEMPT_WINDOW_MINUTES || 15);
const PIX_EXPIRATION_MINUTES = Number(process.env.PIX_EXPIRATION_MINUTES || 15);

// 5 minutos para reduzir replay de webhook
const WEBHOOK_MAX_AGE_MS = 5 * 60 * 1000;

const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID || "";
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || "";
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || "";
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || "";
const R2_OBJECT_KEY = process.env.R2_OBJECT_KEY || "";

const r2 =
  R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY
    ? new S3Client({
        region: "auto",
        endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
        credentials: {
          accessKeyId: R2_ACCESS_KEY_ID,
          secretAccessKey: R2_SECRET_ACCESS_KEY,
        },
      })
    : null;

function logInfo(message, extra = {}) {
  console.log(`[INFO] ${message}`, extra);
}

function logError(message, error, extra = {}) {
  console.error(`[ERROR] ${message}`, {
    ...extra,
    message: error?.message,
    response: error?.response?.data,
    stack: error?.stack,
  });
}

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

function addMinutes(date, minutes) {
  return new Date(date.getTime() + minutes * 60 * 1000);
}

function addDays(date, days) {
  return new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function requireEnv(name, value) {
  if (!value) {
    throw new Error(`Variável ausente: ${name}`);
  }
}

async function query(text, params = []) {
  return pool.query(text, params);
}

async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      order_id TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL,
      payment_id TEXT,
      payment_status TEXT NOT NULL DEFAULT 'pending',
      status TEXT NOT NULL DEFAULT 'pending',
      access_token TEXT NOT NULL UNIQUE,
      email_sent BOOLEAN NOT NULL DEFAULT FALSE,
      email_sent_at TIMESTAMPTZ,
      download_count INTEGER NOT NULL DEFAULT 0,
      last_download_at TIMESTAMPTZ,
      access_link_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS download_sessions (
      id BIGSERIAL PRIMARY KEY,
      order_id TEXT NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
      session_token TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS access_attempts (
      id BIGSERIAL PRIMARY KEY,
      access_token TEXT NOT NULL,
      email_attempt TEXT,
      ip_address TEXT,
      success BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS processed_webhooks (
      id BIGSERIAL PRIMARY KEY,
      request_id TEXT NOT NULL UNIQUE,
      payment_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await query(`CREATE INDEX IF NOT EXISTS idx_orders_order_id ON orders(order_id);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_orders_access_token ON orders(access_token);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_download_sessions_token ON download_sessions(session_token);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_access_attempts_token_created_at ON access_attempts(access_token, created_at);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_processed_webhooks_request_id ON processed_webhooks(request_id);`);
}

function mpHeaders(idempotencyKey) {
  const headers = {
    Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
    "Content-Type": "application/json",
  };

  if (idempotencyKey) {
    headers["X-Idempotency-Key"] = idempotencyKey;
  }

  return headers;
}

async function getPaymentById(paymentId) {
  const response = await axios.get(
    `https://api.mercadopago.com/v1/payments/${paymentId}`,
    { headers: mpHeaders() }
  );
  return response.data;
}

function extractWebhookPaymentId(req) {
  return (
    req.body?.data?.id ||
    req.body?.resource?.split("/").pop() ||
    req.query?.["data.id"] ||
    req.query?.id ||
    null
  );
}

function parseXSignature(signatureHeader = "") {
  const parts = Object.fromEntries(
    String(signatureHeader)
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const [key, ...rest] = part.split("=");
        return [key, rest.join("=")];
      })
      .filter(([key, value]) => key && value)
  );

  return {
    ts: parts.ts || "",
    v1: parts.v1 || "",
  };
}

function safeEqualHex(a, b) {
  try {
    const bufA = Buffer.from(String(a), "hex");
    const bufB = Buffer.from(String(b), "hex");

    if (!bufA.length || !bufB.length || bufA.length !== bufB.length) {
      return false;
    }

    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function normalizeWebhookTimestamp(ts) {
  const raw = String(ts || "").trim();
  if (!/^\d+$/.test(raw)) return NaN;

  if (raw.length <= 10) {
    return Number(raw) * 1000;
  }

  return Number(raw);
}

async function hasProcessedWebhook(requestId) {
  const result = await query(
    `SELECT 1 FROM processed_webhooks WHERE request_id = $1 LIMIT 1`,
    [requestId]
  );
  return Boolean(result.rows[0]);
}

async function markWebhookProcessed(requestId, paymentId = null) {
  await query(
    `INSERT INTO processed_webhooks (request_id, payment_id)
     VALUES ($1, $2)
     ON CONFLICT (request_id) DO NOTHING`,
    [requestId, paymentId ? String(paymentId) : null]
  );
}

async function validateWebhookSignature(req) {
  if (!MP_WEBHOOK_SECRET) {
    return { valid: true, requestId: req.headers["x-request-id"] || null };
  }

  const signatureHeader = req.headers["x-signature"];
  const requestId = req.headers["x-request-id"];

  if (!signatureHeader || !requestId) {
    return { valid: false, reason: "Cabeçalhos obrigatórios ausentes." };
  }

  const { ts, v1 } = parseXSignature(signatureHeader);

  if (!ts || !v1) {
    return { valid: false, reason: "Assinatura incompleta." };
  }

  const tsMs = normalizeWebhookTimestamp(ts);
  if (!Number.isFinite(tsMs)) {
    return { valid: false, reason: "Timestamp inválido." };
  }

  const age = Math.abs(Date.now() - tsMs);
  if (age > WEBHOOK_MAX_AGE_MS) {
    return { valid: false, reason: "Webhook fora da janela de tempo." };
  }

  const dataId = extractWebhookPaymentId(req);
  if (!dataId) {
    return { valid: false, reason: "paymentId ausente no webhook." };
  }

  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;

  const expected = crypto
    .createHmac("sha256", MP_WEBHOOK_SECRET)
    .update(manifest)
    .digest("hex");

  const valid = safeEqualHex(expected, v1);

  return {
    valid,
    requestId,
    paymentId: String(dataId),
    reason: valid ? null : "Hash do webhook não confere.",
  };
}

async function sendAccessEmail(order) {
  if (!resend || !EMAIL_FROM || !BACKEND_PUBLIC_URL) {
    return false;
  }

  const accessUrl = `${BACKEND_PUBLIC_URL}/access/${order.access_token}`;
  const expiresText =
    ORDER_ACCESS_LINK_TTL_DAYS > 0
      ? `Este link-base pode expirar em ${ORDER_ACCESS_LINK_TTL_DAYS} dias.`
      : `Guarde este email. Você pode voltar aqui no futuro para gerar um novo download.`;

  await resend.emails.send({
    from: EMAIL_FROM,
    to: order.email,
    subject: `${PRODUCT_NAME} — pagamento confirmado`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;padding:24px;color:#111">
        <h1 style="margin:0 0 12px">Pagamento confirmado</h1>
        <p style="font-size:16px;line-height:1.6">
          Seu pagamento de <strong>${PRODUCT_NAME}</strong> foi aprovado.
        </p>
        <p style="font-size:16px;line-height:1.6">
          Clique no botão abaixo para acessar sua página de download. Nela, você informará o email usado na compra para liberar um link temporário do arquivo.
        </p>

        <p style="font-size:15px;line-height:1.6;color:#444">
          <strong>Importante:</strong> este pedido permite até <strong>${MAX_DOWNLOADS_PER_ORDER} downloads</strong> do arquivo.
        </p>

        <div style="margin:28px 0">
          <a href="${accessUrl}" style="background:#111;color:#fff;padding:14px 22px;border-radius:10px;text-decoration:none;font-weight:700;display:inline-block">
            Acessar meu download
          </a>
        </div>

        <p style="font-size:14px;line-height:1.6;color:#444">
          ${expiresText}
        </p>

        <p style="font-size:14px;line-height:1.6;color:#444">
          Guarde este email para acessar novamente seu link quando precisar.
        </p>

        <p style="font-size:14px;line-height:1.6;color:#444">
          Se o botão não funcionar, copie e cole este link no navegador:
        </p>
        <p style="word-break:break-all;font-size:13px;color:#444">
          ${accessUrl}
        </p>
      </div>
    `,
  });

  await query(
    `UPDATE orders
     SET email_sent = TRUE, email_sent_at = NOW(), updated_at = NOW()
     WHERE order_id = $1`,
    [order.order_id]
  );

  return true;
}

async function finalizeApprovedPayment(paymentData) {
  const orderId = paymentData.external_reference;
  if (!orderId) return null;

  const result = await query(`SELECT * FROM orders WHERE order_id = $1 LIMIT 1`, [orderId]);
  const order = result.rows[0];
  if (!order) return null;

  await query(
    `UPDATE orders
     SET payment_id = $2,
         payment_status = $3,
         status = CASE WHEN $3 = 'approved' THEN 'approved' ELSE status END,
         updated_at = NOW()
     WHERE order_id = $1`,
    [orderId, String(paymentData.id), paymentData.status]
  );

  const updatedResult = await query(`SELECT * FROM orders WHERE order_id = $1 LIMIT 1`, [orderId]);
  const updatedOrder = updatedResult.rows[0];

  if (paymentData.status === "approved" && !updatedOrder.email_sent) {
    try {
      await sendAccessEmail(updatedOrder);
    } catch (error) {
      logError("Falha ao enviar email após aprovação", error, { orderId });
    }
  }

  return updatedOrder;
}

async function reconcileOrder(order) {
  if (!order?.payment_id || order.payment_status === "approved") {
    return order;
  }

  try {
    const paymentData = await getPaymentById(order.payment_id);
    const updatedOrder = await finalizeApprovedPayment(paymentData);
    return updatedOrder || order;
  } catch (error) {
    logError("Falha na reconciliação do pedido", error, { orderId: order.order_id });
    return order;
  }
}

async function checkR2Health() {
  if (!r2 || !R2_BUCKET_NAME || !R2_OBJECT_KEY) {
    return { ok: false, error: "R2 não configurado" };
  }

  await r2.send(new HeadBucketCommand({ Bucket: R2_BUCKET_NAME }));
  await r2.send(new HeadObjectCommand({ Bucket: R2_BUCKET_NAME, Key: R2_OBJECT_KEY }));
  return { ok: true };
}

app.get("/", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "API online.",
    endpoints: {
      health: "/health",
      createPix: "/api/mercadopago/create-pix",
      paymentStatus: "/api/mercadopago/payment-status/:orderId",
      webhook: "/api/mercadopago/webhook",
      access: "/access/:token",
      download: "/download/:sessionToken",
    },
  });
});

app.get("/health", async (req, res) => {
  let r2Ok = false;
  let r2Error = null;

  try {
    const r2Check = await checkR2Health();
    r2Ok = r2Check.ok;
    r2Error = r2Check.error || null;
  } catch (error) {
    r2Ok = false;
    r2Error = error.message;
  }

  return res.json({
    ok: true,
    time: new Date().toISOString(),
    checks: {
      backendPublicUrl: Boolean(BACKEND_PUBLIC_URL),
      resend: Boolean(resend && EMAIL_FROM),
      mercadoPago: Boolean(MP_ACCESS_TOKEN),
      r2: r2Ok,
      postgres: Boolean(process.env.DATABASE_URL),
      clientUrl: Boolean(CLIENT_URL),
      webhookSecret: Boolean(MP_WEBHOOK_SECRET),
      pixExpirationMinutes: PIX_EXPIRATION_MINUTES,
    },
    ...(r2Error ? { r2Error } : {}),
  });
});

async function handleCreatePix(req, res) {
  try {
    requireEnv("MP_ACCESS_TOKEN", MP_ACCESS_TOKEN);

    const email = normalizeEmail(req.body?.email);
    const confirmEmail = normalizeEmail(req.body?.confirmEmail);

    if (!email || !confirmEmail) {
      return res.status(400).json({
        success: false,
        error: "Preencha os dois campos de email.",
      });
    }

    if (email !== confirmEmail) {
      return res.status(400).json({
        success: false,
        error: "Os emails não coincidem.",
      });
    }

    const orderId = `order_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
    const accessToken = randomToken(24);
    const accessLinkExpiresAt =
      ORDER_ACCESS_LINK_TTL_DAYS > 0 ? addDays(new Date(), ORDER_ACCESS_LINK_TTL_DAYS) : null;

    await query(
      `INSERT INTO orders (order_id, email, payment_status, status, access_token, access_link_expires_at)
       VALUES ($1, $2, 'pending', 'pending', $3, $4)`,
      [orderId, email, accessToken, accessLinkExpiresAt]
    );

    const pixExpiresAt = new Date(
      Date.now() + PIX_EXPIRATION_MINUTES * 60 * 1000
    ).toISOString();

    const paymentData = {
      transaction_amount: PRODUCT_PRICE,
      description: PRODUCT_NAME,
      payment_method_id: "pix",
      external_reference: orderId,
      payer: { email },
      date_of_expiration: pixExpiresAt,
    };

    if (BACKEND_PUBLIC_URL.startsWith("https://")) {
      paymentData.notification_url = `${BACKEND_PUBLIC_URL}/api/mercadopago/webhook`;
    }

    const paymentResponse = await axios.post(
      "https://api.mercadopago.com/v1/payments",
      paymentData,
      { headers: mpHeaders(orderId) }
    );

    const payment = paymentResponse.data;

    await query(
      `UPDATE orders
       SET payment_id = $2, payment_status = $3, updated_at = NOW()
       WHERE order_id = $1`,
      [orderId, String(payment.id), payment.status || "pending"]
    );

    logInfo("Pix criado", {
      orderId,
      paymentId: payment.id,
      email,
      pixExpiresAt,
    });

    return res.json({
      success: true,
      orderId,
      paymentId: payment.id,
      status: payment.status,
      pixCode: payment.point_of_interaction?.transaction_data?.qr_code || "",
      qrCodeBase64: payment.point_of_interaction?.transaction_data?.qr_code_base64 || "",
      expiresAt: payment.date_of_expiration || pixExpiresAt,
    });
  } catch (error) {
    logError("Erro ao criar Pix", error);
    return res.status(500).json({
      success: false,
      error: error?.response?.data?.message || error.message || "Erro ao criar Pix.",
    });
  }
}

app.post("/create-pix", handleCreatePix);
app.post("/api/mercadopago/create-pix", handleCreatePix);

async function handlePaymentStatus(req, res) {
  try {
    const { orderId } = req.params;
    const result = await query(`SELECT * FROM orders WHERE order_id = $1 LIMIT 1`, [orderId]);
    let order = result.rows[0];

    if (!order) {
      return res.status(404).json({
        success: false,
        error: "Pedido não encontrado.",
      });
    }

    order = await reconcileOrder(order);

    return res.json({
      orderId: order.order_id,
      status: order.status,
      paymentStatus: order.payment_status,
      emailSent: order.email_sent,
      accessUrl:
        order.status === "approved" && BACKEND_PUBLIC_URL
          ? `${BACKEND_PUBLIC_URL}/access/${order.access_token}`
          : null,
    });
  } catch (error) {
    logError("Erro ao consultar status do pagamento", error, {
      orderId: req.params.orderId,
    });
    return res.status(500).json({
      success: false,
      error: "Erro ao consultar status.",
    });
  }
}

app.get("/payment-status/:orderId", handlePaymentStatus);
app.get("/api/mercadopago/payment-status/:orderId", handlePaymentStatus);

app.get("/webhook", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Webhook Mercado Pago online.",
    route: "/webhook",
  });
});

app.get("/api/mercadopago/webhook", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Webhook Mercado Pago online.",
    route: "/api/mercadopago/webhook",
  });
});

async function handleWebhook(req, res) {
  try {
    const validation = await validateWebhookSignature(req);

    if (!validation.valid) {
      logInfo("Webhook rejeitado", {
        reason: validation.reason || "Assinatura inválida",
        requestId: req.headers["x-request-id"] || null,
        paymentId: extractWebhookPaymentId(req),
      });

      return res.status(401).json({
        success: false,
        error: "Assinatura inválida.",
      });
    }

    if (validation.requestId && (await hasProcessedWebhook(validation.requestId))) {
      logInfo("Webhook duplicado ignorado", {
        requestId: validation.requestId,
        paymentId: validation.paymentId || null,
      });

      return res.status(200).json({
        success: true,
        duplicate: true,
      });
    }

    const paymentId = validation.paymentId || extractWebhookPaymentId(req);

    if (!paymentId) {
      if (validation.requestId) {
        await markWebhookProcessed(validation.requestId, null);
      }

      return res.status(200).json({
        success: true,
        ignored: true,
      });
    }

    const paymentData = await getPaymentById(paymentId);
    const order = await finalizeApprovedPayment(paymentData);

    if (validation.requestId) {
      await markWebhookProcessed(validation.requestId, paymentId);
    }

    logInfo("Webhook processado", {
      requestId: validation.requestId || null,
      paymentId,
      orderId: paymentData.external_reference,
      status: paymentData.status,
      orderFound: Boolean(order),
    });

    return res.status(200).json({ success: true });
  } catch (error) {
    logError("Erro no webhook", error);
    return res.status(200).json({ success: false, handled: true });
  }
}

app.post("/webhook", handleWebhook);
app.post("/api/mercadopago/webhook", handleWebhook);

app.get("/access/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const result = await query(`SELECT * FROM orders WHERE access_token = $1 LIMIT 1`, [token]);
    const order = result.rows[0];

    if (!order) {
      return res.status(404).send("<h1>Link inválido</h1><p>Pedido não encontrado.</p>");
    }

    if (order.access_link_expires_at && new Date(order.access_link_expires_at) < new Date()) {
      return res.status(410).send("<h1>Link expirado</h1><p>Este link-base expirou.</p>");
    }

    return res.send(`
      <!DOCTYPE html>
      <html lang="pt-BR">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Acessar download</title>
          <style>
            body { font-family: Arial, sans-serif; background: #0f0f0f; color: #fff; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:24px; box-sizing:border-box; }
            .card { width:100%; max-width:520px; background:#161616; border:1px solid rgba(255,255,255,.08); border-radius:20px; padding:28px; }
            h1 { margin:0 0 10px; font-size:28px; }
            p { color:rgba(255,255,255,.78); line-height:1.6; }
            input { width:100%; box-sizing:border-box; padding:14px; margin-top:14px; border-radius:12px; border:1px solid rgba(255,255,255,.12); background:#0f0f0f; color:#fff; }
            button { width:100%; margin-top:16px; padding:14px; border:0; border-radius:12px; font-weight:700; cursor:pointer; }
            .primary { background:#fff; color:#000; }
            .error { margin-top:14px; padding:12px; background:rgba(255,70,70,.12); border:1px solid rgba(255,70,70,.25); border-radius:12px; display:none; }
            .success { margin-top:14px; padding:14px; background:rgba(0,200,120,.12); border:1px solid rgba(0,200,120,.25); border-radius:12px; display:none; }
            a.download { display:none; text-decoration:none; background:#fff; color:#000; padding:14px 18px; border-radius:12px; font-weight:700; margin-top:16px; text-align:center; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>${PRODUCT_NAME}</h1>
            <p>Digite o email usado na compra para liberar seu download.</p>
            <input id="email" type="email" placeholder="Seu email de compra" />
            <button class="primary" id="submit">Liberar download</button>
            <div class="error" id="error"></div>
            <div class="success" id="success"></div>
            <a class="download" id="downloadLink" href="#">Baixar arquivo</a>
          </div>

          <script>
            const button = document.getElementById('submit');
            const emailInput = document.getElementById('email');
            const errorBox = document.getElementById('error');
            const successBox = document.getElementById('success');
            const downloadLink = document.getElementById('downloadLink');

            button.addEventListener('click', async () => {
              errorBox.style.display = 'none';
              successBox.style.display = 'none';
              downloadLink.style.display = 'none';
              button.disabled = true;
              button.textContent = 'Validando...';

              try {
                const response = await fetch('/access/${token}/confirm', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ email: emailInput.value })
                });

                const data = await response.json();

                if (!response.ok || !data.success) {
                  throw new Error(data.error || 'Não foi possível liberar o download.');
                }

                successBox.textContent = 'Tudo certo. Seu download foi liberado.';
                successBox.style.display = 'block';
                downloadLink.href = data.downloadUrl;
                downloadLink.style.display = 'block';
              } catch (error) {
                errorBox.textContent = error.message || 'Erro ao validar acesso.';
                errorBox.style.display = 'block';
              } finally {
                button.disabled = false;
                button.textContent = 'Liberar download';
              }
            });
          </script>
        </body>
      </html>
    `);
  } catch (error) {
    logError("Erro ao abrir página de acesso", error, { token: req.params.token });
    return res.status(500).send("Erro ao abrir página de acesso.");
  }
});

app.post("/access/:token/confirm", async (req, res) => {
  try {
    const { token } = req.params;
    const email = normalizeEmail(req.body?.email);
    const ipAddress =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket.remoteAddress ||
      null;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Informe o email da compra.",
      });
    }

    const attemptsResult = await query(
      `SELECT COUNT(*)::int AS total
       FROM access_attempts
       WHERE access_token = $1
         AND created_at >= NOW() - ($2 || ' minutes')::interval
         AND success = FALSE`,
      [token, ACCESS_ATTEMPT_WINDOW_MINUTES]
    );

    if (attemptsResult.rows[0].total >= MAX_ACCESS_ATTEMPTS_PER_WINDOW) {
      return res.status(429).json({
        success: false,
        error: "Muitas tentativas. Tente novamente mais tarde.",
      });
    }

    const result = await query(`SELECT * FROM orders WHERE access_token = $1 LIMIT 1`, [token]);
    const order = result.rows[0];

    if (!order) {
      await query(
        `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success)
         VALUES ($1, $2, $3, FALSE)`,
        [token, email, ipAddress]
      );
      return res.status(404).json({
        success: false,
        error: "Link inválido.",
      });
    }

    if (order.status !== "approved") {
      return res.status(400).json({
        success: false,
        error: "Pagamento ainda não aprovado.",
      });
    }

    if (order.access_link_expires_at && new Date(order.access_link_expires_at) < new Date()) {
      return res.status(410).json({
        success: false,
        error: "Este link expirou.",
      });
    }

    if (
      Number(MAX_DOWNLOADS_PER_ORDER) > 0 &&
      Number(order.download_count) >= Number(MAX_DOWNLOADS_PER_ORDER)
    ) {
      return res.status(403).json({
        success: false,
        error: "Limite de downloads atingido.",
      });
    }

    if (normalizeEmail(order.email) !== email) {
      await query(
        `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success)
         VALUES ($1, $2, $3, FALSE)`,
        [token, email, ipAddress]
      );
      return res.status(401).json({
        success: false,
        error: "Email diferente do usado na compra.",
      });
    }

    await query(
      `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success)
       VALUES ($1, $2, $3, TRUE)`,
      [token, email, ipAddress]
    );

    const sessionToken = randomToken(24);
    const expiresAt = addMinutes(new Date(), DOWNLOAD_SESSION_MINUTES);

    await query(
      `INSERT INTO download_sessions (order_id, session_token, expires_at, used)
       VALUES ($1, $2, $3, FALSE)`,
      [order.order_id, sessionToken, expiresAt]
    );

    logInfo("Sessão de download criada", {
      orderId: order.order_id,
      sessionToken,
    });

    return res.json({
      success: true,
      downloadUrl: `${BACKEND_PUBLIC_URL}/download/${sessionToken}`,
      expiresAt,
    });
  } catch (error) {
    logError("Erro ao confirmar acesso", error, { token: req.params.token });
    return res.status(500).json({
      success: false,
      error: "Erro ao validar acesso.",
    });
  }
});

app.get("/download/:sessionToken", async (req, res) => {
  try {
    requireEnv("R2_BUCKET_NAME", R2_BUCKET_NAME);
    requireEnv("R2_OBJECT_KEY", R2_OBJECT_KEY);

    if (!r2) {
      throw new Error("R2 não configurado.");
    }

    const { sessionToken } = req.params;

    const sessionResult = await query(
      `SELECT ds.*, o.download_count, o.order_id
       FROM download_sessions ds
       JOIN orders o ON o.order_id = ds.order_id
       WHERE ds.session_token = $1
       LIMIT 1`,
      [sessionToken]
    );

    const session = sessionResult.rows[0];

    if (!session) {
      return res.status(404).send("Sessão de download não encontrada.");
    }

    if (session.used) {
      return res.status(410).send("Este link de download já foi usado.");
    }

    if (new Date(session.expires_at) < new Date()) {
      return res.status(410).send("Este link de download expirou.");
    }

    const command = new GetObjectCommand({
      Bucket: R2_BUCKET_NAME,
      Key: R2_OBJECT_KEY,
    });

    const signedUrl = await getSignedUrl(r2, command, {
      expiresIn: R2_URL_EXPIRES_SECONDS,
    });

    await query(
      `UPDATE download_sessions
       SET used = TRUE, used_at = NOW()
       WHERE session_token = $1`,
      [sessionToken]
    );

    await query(
      `UPDATE orders
       SET download_count = download_count + 1,
           last_download_at = NOW(),
           updated_at = NOW()
       WHERE order_id = $1`,
      [session.order_id]
    );

    logInfo("Download liberado", {
      orderId: session.order_id,
      sessionToken,
    });

    return res.redirect(signedUrl);
  } catch (error) {
    logError("Erro ao liberar download", error, {
      sessionToken: req.params.sessionToken,
    });
    return res.status(500).send("Erro ao liberar download.");
  }
});

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    error: "Rota não encontrada.",
  });
});

async function start() {
  try {
    await initDb();

    app.listen(PORT, () => {
      console.log(`Servidor rodando na porta ${PORT}`);
      console.log(`URL pública esperada: ${BACKEND_PUBLIC_URL || "não definida"}`);
    });
  } catch (error) {
    logError("Erro ao iniciar servidor", error);
    process.exit(1);
  }
}

start();