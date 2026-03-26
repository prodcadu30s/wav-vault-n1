const express = require("express");
const cors = require("cors");
const helmet = require("helmet"); // L4: security headers
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

// L4: helmet — ~15 security headers (X-Frame-Options, HSTS, CSP, nosniff, etc.)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'unsafe-inline'"], // necessário para o inline JS da página /access/:token
      styleSrc:   ["'unsafe-inline'"],
    },
  },
}));

// M7: JSON reviver — bloqueia prototype pollution (__proto__, constructor, prototype)
app.use(express.json({
  limit: "1mb",
  reviver: (key, value) => {
    if (key === "__proto__" || key === "constructor" || key === "prototype") return undefined;
    return value;
  },
}));

app.use(
  cors({
    origin: process.env.CLIENT_URL
      ? process.env.CLIENT_URL.replace(/\/$/, "")
      : false,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-signature", "x-request-id"],
  })
);

// C3: trust proxy configurável — set TRUST_PROXY=1 em Railway/Render para obter IP real via req.ip
if (process.env.TRUST_PROXY) {
  app.set("trust proxy", Number(process.env.TRUST_PROXY) || 1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // L3: rejectUnauthorized configurável — set DATABASE_SSL_REJECT_UNAUTHORIZED=true se o provedor tiver cert válido
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: process.env.DATABASE_SSL_REJECT_UNAUTHORIZED === "true" }
    : false,
});

const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

const PORT = Number(process.env.PORT || 3000);
const CLIENT_URL = (process.env.CLIENT_URL || "").replace(/\/$/, "");
const BACKEND_PUBLIC_URL = (process.env.BACKEND_PUBLIC_URL || "").replace(/\/$/, "");
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || "";
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "";
const PRODUCT_NAME = process.env.PRODUCT_NAME || "WAV Vault Vol. 1";
// A9: sanitizar PRODUCT_NAME — elimina risco de header injection no email e XSS no HTML
const SAFE_PRODUCT_NAME = PRODUCT_NAME.replace(/[\r\n<>"'&]/g, "");
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
    stack: process.env.NODE_ENV !== "production" ? error?.stack : undefined,
  });
}

// A2: mascarar tokens nos logs
function maskToken(token) {
  if (!token || token.length <= 8) return "***";
  return token.slice(0, 8) + "...";
}

// A3: mascarar email nos logs
function maskEmail(email) {
  if (!email || !email.includes("@")) return "***";
  const [local, domain] = email.split("@");
  return local.slice(0, 2) + "***@" + domain;
}

// A4: escape HTML para interpolações seguras em HTML gerado
function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// M5: validação de formato de email
function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length >= 3 &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
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

// C1/C2: rate limiter em memória (sem dependência externa, adequado para processo único)
const rateLimitStore = new Map();
function checkRateLimit(key, maxRequests, windowMs) {
  if (!key) return false;
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  if (entry.count >= maxRequests) return true;
  entry.count++;
  return false;
}
// Limpar entradas expiradas a cada 10 min para não vazar memória
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitStore) if (now > v.resetAt) rateLimitStore.delete(k);
}, 10 * 60 * 1000).unref();

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
  // C3/A7: índice por IP para rate limit no /payment-success
  await query(`CREATE INDEX IF NOT EXISTS idx_access_attempts_ip_created_at ON access_attempts(ip_address, created_at);`);
  await query(`CREATE INDEX IF NOT EXISTS idx_processed_webhooks_request_id ON processed_webhooks(request_id);`);

  // M3/M4/M8: limpar registros antigos a cada restart — maném performance dos índices
  await query(`DELETE FROM processed_webhooks WHERE created_at < NOW() - INTERVAL '7 days';`);
  await query(`DELETE FROM access_attempts   WHERE created_at < NOW() - INTERVAL '30 days';`);
  await query(`DELETE FROM download_sessions  WHERE created_at < NOW() - INTERVAL '30 days';`);
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
  // C6: timeout de 10s — sem timeout a chamada pode travar indefinidamente e esgotar o pool do banco
  const response = await axios.get(
    `https://api.mercadopago.com/v1/payments/${paymentId}`,
    { headers: mpHeaders(), timeout: 10000 }
  );
  return response.data;
}

function extractWebhookPaymentId(req) {
  // M1: truncar resource antes de split() — evita alocação excessiva / ReDoS
  const resource = String(req.body?.resource || "").slice(0, 500);
  return (
    req.body?.data?.id ||
    resource.split("/").pop() ||
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

  // A8: garantir que paymentId é numérico — evita path traversal na URL da API do MP
  if (!/^\d+$/.test(String(dataId))) {
    return { valid: false, reason: "paymentId com formato inválido." };
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

async function sendAccessEmail(order, { retries = 3, delayMs = 1000 } = {}) {
  if (!resend || !EMAIL_FROM || !BACKEND_PUBLIC_URL) {
    return false;
  }

  const accessUrl = `${BACKEND_PUBLIC_URL}/access/${order.access_token}`;
  const expiresText =
    ORDER_ACCESS_LINK_TTL_DAYS > 0
      ? `Este link-base pode expirar em ${ORDER_ACCESS_LINK_TTL_DAYS} dias.`
      : `Guarde este email. Você pode voltar aqui no futuro para gerar um novo download.`;

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;padding:24px;color:#111">
      <h1 style="margin:0 0 12px">Pagamento confirmado</h1>
      <p style="font-size:16px;line-height:1.6">
        Seu pagamento de <strong>${escapeHtml(SAFE_PRODUCT_NAME)}</strong> foi aprovado.
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
  `;

  let lastError;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await resend.emails.send({
        from: EMAIL_FROM,
        to: order.email,
        // A9: usar SAFE_PRODUCT_NAME — elimitana header injection (\r\n no subject) e XSS no HTML
        subject: `${SAFE_PRODUCT_NAME} — pagamento confirmado`,
        html,
      });

      await query(
        `UPDATE orders
         SET email_sent = TRUE, email_sent_at = NOW(), updated_at = NOW()
         WHERE order_id = $1`,
        [order.order_id]
      );

      return true;
    } catch (error) {
      lastError = error;
      logError(`Tentativa ${attempt}/${retries} de envio de email falhou`, error, { orderId: order.order_id });
      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, delayMs * attempt));
      }
    }
  }

  logError("Todas as tentativas de envio de email falharam", lastError, { orderId: order.order_id });
  return false;
}

async function finalizeApprovedPayment(paymentData) {
  const orderId = paymentData.external_reference;
  if (!orderId) return null;

  const result = await query(
    `SELECT order_id, email, status, payment_status, payment_id, email_sent,
            download_count, access_token, access_link_expires_at
     FROM orders WHERE order_id = $1 LIMIT 1`,
    [orderId]
  );
  const order = result.rows[0];
  if (!order) return null;

  // C5: verificar que o paymentId do webhook bate com o que o servidor registrou
  // Impede external_reference hijacking: atacante não consegue aprovar pedidos alheios
  // criando um pagamento próprio com external_reference de outra pessoa.
  if (order.payment_id && String(paymentData.id) !== order.payment_id) {
    logError("Mismatch de paymentId no webhook — possível hijacking", null, {
      orderId,
      expected: order.payment_id,
      received: String(paymentData.id),
    });
    return null;
  }

  // C4: chargeback/reembolso REVOGA o acesso ao download
  // O campo `status` agora desce para 'revoked' em caso de cancelamento/estorno.
  // O check `session.status !== 'approved'` no /download bloqueia automaticamente.
  await query(
    `UPDATE orders
     SET payment_id = $2,
         payment_status = $3,
         status = CASE
           WHEN $3 = 'approved'                              THEN 'approved'
           WHEN $3 IN ('refunded','charged_back','cancelled') THEN 'revoked'
           ELSE status
         END,
         updated_at = NOW()
     WHERE order_id = $1`,
    [orderId, String(paymentData.id), paymentData.status]
  );

  const updatedResult = await query(
    `SELECT order_id, email, status, payment_status, payment_id, email_sent,
            download_count, access_token, access_link_expires_at
     FROM orders WHERE order_id = $1 LIMIT 1`,
    [orderId]
  );
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

// L2: remover lista de endpoints — reduz superficie de reconhecimento para atacantes
app.get("/", (req, res) => {
  return res.status(200).json({ success: true, message: "API online." });
});

// L1: /health com auth opcional — set HEALTH_TOKEN na env para proteger
app.get("/health", async (req, res) => {
  const healthToken = process.env.HEALTH_TOKEN;
  if (healthToken) {
    const provided = req.headers["authorization"]?.replace("Bearer ", "");
    if (provided !== healthToken) {
      return res.status(401).json({ success: false, error: "Não autorizado." });
    }
  }

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

  // L1: remover pixExpirationMinutes e dados internos desnecessarios
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
    },
    ...(r2Error ? { r2Error } : {}),
  });
});

async function handleCreatePix(req, res) {
  try {
    requireEnv("MP_ACCESS_TOKEN", MP_ACCESS_TOKEN);

    // C2: rate limit por IP — máx 3 criações de PIX por janela por IP
    const ip = req.ip || req.socket?.remoteAddress || null;
    if (checkRateLimit(`pix:${ip}`, 3, ACCESS_ATTEMPT_WINDOW_MINUTES * 60 * 1000)) {
      return res.status(429).json({ success: false, error: "Muitas tentativas. Tente novamente mais tarde." });
    }

    const email = normalizeEmail(req.body?.email);
    const confirmEmail = normalizeEmail(req.body?.confirmEmail);

    if (!email || !confirmEmail) {
      return res.status(400).json({ success: false, error: "Preencha os dois campos de email." });
    }

    // M5: validação de formato de email
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: "Email inválido." });
    }

    if (email !== confirmEmail) {
      return res.status(400).json({ success: false, error: "Os emails não coincidem." });
    }

    const orderId = `order_${randomToken(12)}`;
    const accessToken = randomToken(24);
    const accessLinkExpiresAt =
      ORDER_ACCESS_LINK_TTL_DAYS > 0 ? addDays(new Date(), ORDER_ACCESS_LINK_TTL_DAYS) : null;

    await query(
      `INSERT INTO orders (order_id, email, payment_status, status, access_token, access_link_expires_at)
       VALUES ($1, $2, 'pending', 'pending', $3, $4)`,
      [orderId, email, accessToken, accessLinkExpiresAt]
    );

    const pixExpiresAt = new Date(Date.now() + PIX_EXPIRATION_MINUTES * 60 * 1000).toISOString();

    const paymentData = {
      transaction_amount: PRODUCT_PRICE,
      description: SAFE_PRODUCT_NAME,
      payment_method_id: "pix",
      external_reference: orderId,
      payer: { email },
      date_of_expiration: pixExpiresAt,
    };

    if (BACKEND_PUBLIC_URL.startsWith("https://")) {
      paymentData.notification_url = `${BACKEND_PUBLIC_URL}/api/mercadopago/webhook`;
    }

    // C6: timeout de 15s na criação do PIX
    const paymentResponse = await axios.post(
      "https://api.mercadopago.com/v1/payments",
      paymentData,
      { headers: mpHeaders(orderId), timeout: 15000 }
    );

    const payment = paymentResponse.data;

    await query(
      `UPDATE orders SET payment_id = $2, payment_status = $3, updated_at = NOW() WHERE order_id = $1`,
      [orderId, String(payment.id), payment.status || "pending"]
    );

    // A3: mascarar email no log
    logInfo("Pix criado", { orderId, paymentId: payment.id, email: maskEmail(email), pixExpiresAt });

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
    // M9: não expor mensagem interna do MP ao cliente
    return res.status(500).json({ success: false, error: "Erro ao processar pagamento. Tente novamente." });
  }
}

app.post("/create-pix", handleCreatePix);
app.post("/api/mercadopago/create-pix", handleCreatePix);

async function handlePaymentStatus(req, res) {
  try {
    const { orderId } = req.params;

    // M2: validar tamanho do orderId
    if (!orderId || orderId.length > 200) {
      return res.status(400).json({ success: false, error: "ID inválido." });
    }

    // C1: rate limit por IP — máx 30 polls por minuto
    const ip = req.ip || req.socket?.remoteAddress || null;
    if (checkRateLimit(`status:${ip}`, 30, 60 * 1000)) {
      return res.status(429).json({ success: false, error: "Muitas tentativas. Tente novamente mais tarde." });
    }

    const result = await query(
      `SELECT order_id, status, payment_status, payment_id, email_sent,
              download_count, access_link_expires_at
       FROM orders WHERE order_id = $1 LIMIT 1`,
      [orderId]
    );
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
      // FIX #4: accessUrl removido — o link de acesso chega SOMENTE por email
      // Expor o accessUrl aqui permitiria que qualquer pessoa com o orderId
      // (que é público) obtivesse o link sem precisar do email da compra.
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

// Endpoint Opção C: retorna o accessUrl SOMENTE se o pedido está aprovado
// E o email informado bate com o email da compra.
// Usado pelo frontend para redirecionar o comprador imediatamente após o pagamento,
// sem esperar o email — mas sem expor o link para quem não tem o email da compra.
async function handlePaymentSuccess(req, res) {
  try {
    const { orderId } = req.params;

    // M2: validar tamanho do orderId
    if (!orderId || orderId.length > 200) {
      return res.status(400).json({ success: false, error: "ID inválido." });
    }

    const email = normalizeEmail(req.body?.email);
    // C3: usar req.ip (respeita trust proxy) em vez de parsear X-Forwarded-For manualmente
    const ipAddress = req.ip || req.socket?.remoteAddress || null;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Informe o email usado na compra.",
      });
    }

    // M5: validação de formato de email
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: "Email inválido." });
    }


    // Rate limiting: reutiliza a tabela access_attempts para bloquear brute force
    // de orderId + email. Conta tentativas falhas do IP na janela de tempo.
    const attemptsResult = await query(
      `SELECT COUNT(*)::int AS total
       FROM access_attempts
       WHERE ip_address = $1
         AND created_at >= NOW() - ($2 || ' minutes')::interval
         AND success = FALSE`,
      [ipAddress, ACCESS_ATTEMPT_WINDOW_MINUTES]
    );

    if (attemptsResult.rows[0].total >= MAX_ACCESS_ATTEMPTS_PER_WINDOW) {
      return res.status(429).json({
        success: false,
        error: "Muitas tentativas. Tente novamente mais tarde.",
      });
    }

    const result = await query(
      `SELECT order_id, email, status, payment_status, access_token, access_link_expires_at
       FROM orders WHERE order_id = $1 LIMIT 1`,
      [orderId]
    );
    const order = result.rows[0];

    // A1: delay constante antes de erros — reduz timing side-channel
    const genericError = async () => {
      await new Promise((r) => setTimeout(r, 50));
      return res.status(401).json({
        success: false,
        error: "Dados não conferem ou pagamento ainda não aprovado.",
      });
    };

    if (!order) {
      await query(
        `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success) VALUES ($1, $2, $3, FALSE)`,
        [orderId, maskEmail(email), ipAddress]
      );
      return genericError();
    }

    if (order.status !== "approved") {
      return genericError();
    }

    if (normalizeEmail(order.email) !== email) {
      await query(
        `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success) VALUES ($1, $2, $3, FALSE)`,
        [order.access_token, maskEmail(email), ipAddress]
      );
      return genericError();
    }

    if (order.access_link_expires_at && new Date(order.access_link_expires_at) < new Date()) {
      return res.status(410).json({ success: false, error: "O link de acesso deste pedido expirou." });
    }

    await query(
      `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success) VALUES ($1, $2, $3, TRUE)`,
      [order.access_token, maskEmail(email), ipAddress]
    );

    // A3: mascarar email no log
    logInfo("payment-success: accessUrl liberado", { orderId, email: maskEmail(email) });

    return res.json({ success: true, accessUrl: `${BACKEND_PUBLIC_URL}/access/${order.access_token}` });
  } catch (error) {
    logError("Erro ao processar payment-success", error, {
      orderId: req.params.orderId,
    });
    return res.status(500).json({
      success: false,
      error: "Erro ao verificar pedido.",
    });
  }
}

app.post("/payment-success/:orderId", handlePaymentSuccess);
app.post("/api/mercadopago/payment-success/:orderId", handlePaymentSuccess);

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
    // M2: validar tamanho do token
    if (!token || token.length > 200) {
      return res.status(400).send("<h1>Token inválido</h1>");
    }
    const result = await query(
      `SELECT order_id, email, status, payment_status, access_token,
              access_link_expires_at, download_count
       FROM orders WHERE access_token = $1 LIMIT 1`,
      [token]
    );
    const order = result.rows[0];

    if (!order) {
      return res.status(404).send("<h1>Link inválido</h1><p>Pedido não encontrado.</p>");
    }

    if (order.access_link_expires_at && new Date(order.access_link_expires_at) < new Date()) {
      return res.status(410).send("<h1>Link expirado</h1><p>Este link-base expirou.</p>");
    }

    // A4: usar SAFE_PRODUCT_NAME com escapeHtml no título da página
    const safeTitle = escapeHtml(SAFE_PRODUCT_NAME);
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
          <h1>${safeTitle}</h1>
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
                if (data.downloadUrl) {
                  downloadLink.href = data.downloadUrl;
                  downloadLink.style.display = 'block';
                }
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
    logError("Erro ao abrir página de acesso", error, { token: maskToken(req.params.token) });
    return res.status(500).send("Erro ao abrir página de acesso.");
  }
});

app.post("/access/:token/confirm", async (req, res) => {
  try {
    const { token } = req.params;
    // M2: validar tamanho do token
    if (!token || token.length > 200) {
      return res.status(400).json({ success: false, error: "Token inválido." });
    }
    const email = normalizeEmail(req.body?.email);
    const ipAddress = req.ip || req.socket?.remoteAddress || null;

    if (!email) {
      return res.status(400).json({ success: false, error: "Informe o email da compra." });
    }
    // M5: validação de formato de email
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: "Email inválido." });
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

    // FIX #6: SELECT explícito
    const result = await query(
      `SELECT order_id, email, status, access_link_expires_at, download_count
       FROM orders WHERE access_token = $1 LIMIT 1`,
      [token]
    );
    const order = result.rows[0];

    if (!order) {
      await query(
        `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success) VALUES ($1, $2, $3, FALSE)`,
        [token, maskEmail(email), ipAddress]
      );
      return res.status(404).json({ success: false, error: "Link inválido." });
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

    // Pré-verificação do limite (não atômica, mas serve para feedback rápido ao usuário)
    // A verificação atômica real acontece no /download/:sessionToken (FIX #2)
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
        `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success) VALUES ($1, $2, $3, FALSE)`,
        [token, maskEmail(email), ipAddress]
      );
      return res.status(401).json({ success: false, error: "Email diferente do usado na compra." });
    }

    // A7: verificar se já existe sessão ativa (não usada, não expirada) para este pedido
    // Evita acumulo de múltiplas sessões em paralelo
    const activeSession = await query(
      `SELECT session_token FROM download_sessions
       WHERE order_id = $1 AND used = FALSE AND expires_at > NOW()
       LIMIT 1`,
      [order.order_id]
    );
    if (activeSession.rows[0]) {
      const existingToken = activeSession.rows[0].session_token;
      await query(
        `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success) VALUES ($1, $2, $3, TRUE)`,
        [token, maskEmail(email), ipAddress]
      );
      logInfo("Sessão ativa reutilizada", { orderId: order.order_id, sessionToken: maskToken(existingToken) });
      return res.json({ success: true, downloadUrl: `${BACKEND_PUBLIC_URL}/download/${existingToken}` });
    }

    await query(
      `INSERT INTO access_attempts (access_token, email_attempt, ip_address, success) VALUES ($1, $2, $3, TRUE)`,
      [token, maskEmail(email), ipAddress]
    );

    const sessionToken = randomToken(24);
    const expiresAt = addMinutes(new Date(), DOWNLOAD_SESSION_MINUTES);

    await query(
      `INSERT INTO download_sessions (order_id, session_token, expires_at, used)
       VALUES ($1, $2, $3, FALSE)`,
      [order.order_id, sessionToken, expiresAt]
    );

    // A2: mascarar token no log
    logInfo("Sessão de download criada", {
      orderId: order.order_id,
      sessionToken: maskToken(sessionToken),
    });

    return res.json({ success: true, downloadUrl: `${BACKEND_PUBLIC_URL}/download/${sessionToken}`, expiresAt });
  } catch (error) {
    logError("Erro ao confirmar acesso", error, { token: maskToken(req.params.token) });
    return res.status(500).json({ success: false, error: "Erro ao validar acesso." });
  }
});

app.get("/download/:sessionToken", async (req, res) => {
  try {
    requireEnv("R2_BUCKET_NAME", R2_BUCKET_NAME);
    requireEnv("R2_OBJECT_KEY", R2_OBJECT_KEY);

    if (!r2) throw new Error("R2 não configurado.");

    const { sessionToken } = req.params;
    // M2: validar tamanho do sessionToken
    if (!sessionToken || sessionToken.length > 200) {
      return res.status(400).send("Token inválido.");
    }

    // FIX #3: buscar também o status do pedido para revalidar na hora do download
    const sessionResult = await query(
      `SELECT ds.session_token, ds.used, ds.expires_at, ds.order_id,
              o.download_count, o.status
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

    // FIX #3: revalidar status do pedido (ex: chargeback após sessão criada)
    if (session.status !== "approved") {
      return res.status(403).send("Pedido não está aprovado.");
    }

    // FIX #2: UPDATE atômico com verificação de limite
    // Incrementa download_count SOMENTE se ainda estiver abaixo do limite.
    // Isso elimina a race condition: duas requisições simultâneas não podem
    // ambas passar, pois o banco garante atomicidade do UPDATE.
    const updateResult = await query(
      `UPDATE orders
       SET download_count = download_count + 1,
           last_download_at = NOW(),
           updated_at = NOW()
       WHERE order_id = $1
         AND (download_count < $2 OR $2 = 0)
       RETURNING download_count`,
      [session.order_id, MAX_DOWNLOADS_PER_ORDER]
    );

    if (updateResult.rowCount === 0) {
      // Limite atingido — outra requisição simultânea já consumiu o último slot
      return res.status(403).send("Limite de downloads atingido.");
    }

    const command = new GetObjectCommand({
      Bucket: R2_BUCKET_NAME,
      Key: R2_OBJECT_KEY,
    });

    const signedUrl = await getSignedUrl(r2, command, {
      expiresIn: R2_URL_EXPIRES_SECONDS,
    });

    // Marcar sessão como usada somente após garantir o slot (FIX #2)
    await query(
      `UPDATE download_sessions
       SET used = TRUE, used_at = NOW()
       WHERE session_token = $1`,
      [sessionToken]
    );

    logInfo("Download liberado", {
      orderId: session.order_id,
      sessionToken: maskToken(sessionToken),
      newDownloadCount: updateResult.rows[0]?.download_count,
    });

    return res.redirect(signedUrl);
  } catch (error) {
    logError("Erro ao liberar download", error, { sessionToken: maskToken(req.params.sessionToken) });
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
    if (!MP_WEBHOOK_SECRET) {
      throw new Error("MP_WEBHOOK_SECRET não configurado. Configure esta variável antes de iniciar o servidor.");
    }

    await initDb();

    // A6: timeouts de servidor — mitiga Slowloris e conexões penduradas indefinidamente
    const server = app.listen(PORT, () => {
      console.log(`Servidor rodando na porta ${PORT}`);
      console.log(`URL pública esperada: ${BACKEND_PUBLIC_URL || "não definida"}`);
    });
    server.headersTimeout  = 15000; // 15s para receber todos os headers
    server.requestTimeout  = 60000; // 60s para completar a requisição
    server.keepAliveTimeout = 5000; // fecha conexões idle
  } catch (error) {
    logError("Erro ao iniciar servidor", error);
    process.exit(1);
  }
}

start();