import {
  generateSignature,
  verifySignature,
  generateSignatureHeader,
  verifySignatureHeader,
} from "./index.js";

const gp = {
  appid: "1234567890",
  secretKey: "1234567890",
  url: "/query",
  method: "GET",
  timestamp: Math.floor(Date.now() / 1000),
  nonce: "1234567890",
};
const header = await generateSignatureHeader({ pairValue: true, ...gp });
console.log(header);

const res = await verifySignatureHeader({
  headerValue: header.headerValue,
  url: gp.url,
  query: gp.query,
  method: gp.method,
  body: gp.body,
  pairValue: true,
  getSecretkeyByAppid: async (appid) => {
    console.log(appid);
    return gp.secretKey;
  },
});
