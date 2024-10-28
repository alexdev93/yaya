const express = require("express");
const crypto = require("crypto");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
require("dotenv").config();

const app = express();
app.use(express.json());

// Function to verify signature
const verifySignature = (payload, signature) => {
  const signedPayload = Object.values(payload).join("");
  const hmac = crypto.createHmac("sha256", process.env.SECRET_KEY);
  hmac.update(signedPayload, "utf8");
  const expectedSignature = hmac.digest("hex");
  return expectedSignature === signature;
};

app.post("/webhook", async (req, res) => {
  const signature = req.headers["yaya-signature"];
  const payload = req.body;

  // Signature verification
  if (!verifySignature(payload, signature)) {
    return res.status(403).send("Forbidden");
  }

  // Timestamp verification for replay attack protection
  const currentTime = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTime - payload.timestamp) > 300) {
    return res.status(400).send("Timestamp out of range");
  }

  // Save transaction to the database
  try {
    await prisma.transaction.create({
      data: {
        id: payload.id,
        amount: payload.amount,
        currency: payload.currency,
        createdAt: payload.created_at_time,
        timestamp: payload.timestamp,
        cause: payload.cause,
        fullName: payload.full_name,
        accountName: payload.account_name,
        invoiceUrl: payload.invoice_url,
      },
    });
    return res.status(200).send("Event processed");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Server error");
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
