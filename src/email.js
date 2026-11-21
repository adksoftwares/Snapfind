const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (ch) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[ch]));

async function sendPasswordResetEmail(config, recipient, resetUrl) {
  const provider = config.resetEmailProviderConfig;
  if (config.resetEmailConfigured !== true || provider.provider !== "resend") throw new Error("Reset email provider is not configured");
  const safeUrl = escapeHtml(resetUrl);
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${provider.resendApiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: provider.from, to: [recipient], subject: "Reset your SnapFind password",
      text: `We received a request to reset your SnapFind password. This link expires in 30 minutes: ${resetUrl}\n\nIf you did not request this, ignore this email.`,
      html: `<p>We received a request to reset your SnapFind password.</p><p><a href="${safeUrl}">Reset password</a> (expires in 30 minutes)</p><p>If you did not request this, ignore this email.</p>`,
    }),
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Resend rejected the message (HTTP ${response.status})`);
}
module.exports = { sendPasswordResetEmail };
