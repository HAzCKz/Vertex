function validateNonEmptyString(v, name) {
  if (typeof v !== "string" || !v.trim()) {
    const e = new Error(`Campo inválido: ${name}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: name };
    throw e;
  }
}

module.exports = { validateNonEmptyString };
