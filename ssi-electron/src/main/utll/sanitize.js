function sanitizeError(e) {
  const code = e?.code || "INTERNAL_ERROR";
  const message = e?.message || String(e);

  // Evite vazar segredos aqui. Se no futuro você tiver erros com pass/seed,
  // trate e mascare.
  const details = e?.details ? safeClone(e.details) : undefined;

  return { code, message, details };
}

function safeClone(obj) {
  try {
    return JSON.parse(JSON.stringify(obj));
  } catch (_) {
    return undefined;
  }
}

module.exports = { sanitizeError };
