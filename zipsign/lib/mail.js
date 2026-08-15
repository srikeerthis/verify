import nodemailer from 'nodemailer';

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (!process.env.SMTP_URL) return null;
  transporter = nodemailer.createTransport(process.env.SMTP_URL);
  return transporter;
}

export async function sendOtp(email, otp) {
  const t = getTransporter();
  if (!t) {
    console.log(`[otp] no SMTP configured - verification code for ${email}: ${otp}`);
    return { delivered: false };
  }
  await t.sendMail({
    from: process.env.MAIL_FROM || 'Verify <no-reply@verify.local>',
    to: email,
    subject: 'Your Verify code',
    text: `Your verification code is: ${otp}\n\nIt expires in 10 minutes. If you did not request it, ignore this email.`,
    html: `<p>Your verification code is: <b style="font-size:18px;letter-spacing:2px">${otp}</b></p><p>It expires in 10 minutes. If you did not request it, ignore this email.</p>`,
  });
  return { delivered: true };
}
