async function sendEmail(to, subject, text) {
  // For dev purposes – just log it
  console.log(`Sending email to ${to}\nSubject: ${subject}\n\n${text}`);
  // In production, use nodemailer/sendgrid
}

module.exports = sendEmail;
