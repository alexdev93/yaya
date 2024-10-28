// webhook.test.js
require("dotenv").config();
const request = require("supertest");
const crypto = require("crypto");
const app = require("../src/app");
const prisma = require("../src/PrismaClient");

describe("YaYa Wallet Webhook", () => {
  let validPayload;
  let validSignature;

  beforeAll(() => {
    // Sample payload
    validPayload = {
      id: "12345",
      amount: 100,
      currency: "USD",
      created_at_time: new Date().toISOString(),
      timestamp: Math.floor(Date.now() / 1000),
      cause: "Payment for services",
      full_name: "John Doe",
      account_name: "john.doe@example.com",
      invoice_url: "http://example.com/invoice/12345",
    };

    // Generate valid signature
    const signedPayload = Object.values(validPayload).join("");
    const hmac = crypto.createHmac("sha256", process.env.SECRET_KEY);
    hmac.update(signedPayload, "utf8");
    validSignature = hmac.digest("hex");
  });

  it("should respond with 200 for valid payload", async () => {
    const response = await request(app)
      .post("/webhook")
      .set("yaya-signature", validSignature)
      .send(validPayload);

    expect(response.status).toBe(200);
    expect(response.text).toBe("Event processed");
  });

  it("should respond with 403 for invalid signature", async () => {
    const response = await request(app)
      .post("/webhook")
      .set("yaya-signature", "invalid_signature")
      .send(validPayload);

    expect(response.status).toBe(403);
    expect(response.text).toBe("Forbidden");
  });

  it("should respond with 400 for timestamp out of range", async () => {
    const invalidPayload = {
      ...validPayload,
      timestamp: Math.floor(Date.now() / 1000) - 400, // Simulate an old timestamp
    };

    const response = await request(app)
      .post("/webhook")
      .set("yaya-signature", validSignature)
      .send(invalidPayload);

    expect(response.status).toBe(400);
    expect(response.text).toBe("Timestamp out of range");
  });

  it("should respond with 500 for server error", async () => {
    // Mock Prisma create method to throw an error
    jest.spyOn(prisma.transaction, "create").mockImplementationOnce(() => {
      throw new Error("Database error");
    });

    const response = await request(app)
      .post("/webhook")
      .set("yaya-signature", validSignature)
      .send(validPayload);

    expect(response.status).toBe(500);
    expect(response.text).toBe("Server error");
  });
});
