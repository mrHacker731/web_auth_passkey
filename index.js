const express = require("express");
const app = express();
const crypto = require("node:crypto");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

app.use(express.static("./public"));
app.use(express.json());

const userStore = {};
const challengeStore = {};

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const id = `user_${Date.now()}`;

  const user = {
    id,
    username,
    password,
  };

  userStore[id] = user;

  console.log(`Register successful`, userStore[id]);

  return res.json({ id });
});

app.post("/register-challenge", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });

  const user = userStore[userId];

  const challengePayload = await generateRegistrationOptions({
    rpID: "web-auth-passkey.onrender.com",  // No https:// here
    rpName: "My Render Deployed App",
    attestationType: "none",
    userName: user.username,
    timeout: 30_000,
  });

  challengeStore[userId] = challengePayload.challenge;

  return res.json({ options: challengePayload });
});

// verify register
app.post("/register-verify", async (req, res) => {
  const { userId, cred } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });

  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const verificationResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "https://web-auth-passkey.onrender.com",  // Include https:// here
    expectedRPID: "web-auth-passkey.onrender.com",  // No https:// here
    response: cred,
  });

  if (!verificationResult.verified)
    return res.json({ error: "could not verify" });
  userStore[userId].passkey = verificationResult.registrationInfo;

  return res.json({ verified: true });
});

app.post("/login-challenge", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "user not found!" });

  const user = userStore[userId];

  const opt = await generateAuthenticationOptions({
    rpID: "web-auth-passkey.onrender.com",  // No https:// here
  });

  challengeStore[userId] = opt.challenge;

  return res.json({ option: opt });
});

app.post('/login-verify', async (req, res) => {
    const { userId, cred }  = req.body

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
    const user = userStore[userId]
    const challenge = challengeStore[userId]

    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'https://web-auth-passkey.onrender.com',  // Include https:// here
        expectedRPID: 'web-auth-passkey.onrender.com',  // No https:// here
        response: cred,
        authenticator: user.passkey
    })

    if (!result.verified) return res.json({ error: 'something went wrong' })
    
    // Login the user: Session, Cookies, JWT
    return res.json({ success: true, userId })
})

const port = 3000;
app.listen(port, () => {
  console.log("listening on port " + port);
});
