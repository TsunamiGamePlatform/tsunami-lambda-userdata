function sanitizeHtml(html) {
  // Escape special regex characters inside []
  const allowedChars = "A-Za-z0-9!$%^&*()_+=|;\\. \\n";

  // Notice: - and . must be escaped or moved to the end safely
  const dirtyRegex = new RegExp(`[^${allowedChars}-]`, "g");

  return dirtyRegex.test(html);
}
function sanitizeBirthday(birthday) {
  // Check ISO format first
  const isoRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!isoRegex.test(birthday)) return true; // invalid

  const [yearStr, monthStr, dayStr] = birthday.split("-");
  const year = Number(yearStr);
  const month = Number(monthStr) - 1; // JS months 0-11
  const day = Number(dayStr);

  const date = new Date(year, month, day);
  // Check if date matches input (avoids JS auto-correction like Feb 30 -> Mar 2)
  if (
    date.getFullYear() !== year ||
    date.getMonth() !== month ||
    date.getDate() !== day
  ) {
    return true; // invalid
  }

  return false; // clean
}
function sanitizeEmail(email) {
  const dirtyRegex = /[^A-Za-z0-9.@_-]/g; // allow letters, digits, dot, @, underscore, hyphen
  return dirtyRegex.test(email); // true = invalid
}
const sanitizedUsername = sanitizeEmail("hi@exa<>mple.com");
console.log(sanitizedUsername);
