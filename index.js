import { hmacHash } from "ph-utils/crypto";
import { random } from "ph-utils";

/**
 * 将查询参数对象或 URLSearchParams 转换为查询字符串
 * @param {Object|URLSearchParams} query - 查询参数对象或 URLSearchParams 实例
 * @returns {string} 返回格式化后的查询字符串,以'?'开头,如果 query 为空则返回空字符串
 */
function queryStringify(query) {
  if (query) {
    let q;
    if (!(query instanceof URLSearchParams)) {
      q = new URLSearchParams(query);
    } else {
      q = query;
    }
    const qstr = q.toString();
    return `${qstr ? "?" : ""}${qstr}`;
  }
  return "";
}

function parseSignatureItem(signatureStr, pairValue = false) {
  if (pairValue) {
    return signatureStr.split("&").reduce((acc, cur) => {
      const [key, value] = cur.split("=");
      acc[key.trim()] = value.trim();
      return acc;
    }, {});
  }
  const sigItem = signatureStr.split(":");
  return {
    appid: sigItem[0],
    timestamp: sigItem[1],
    nonce: sigItem[2],
    signature: sigItem[3],
  };
}

/**
 * @typedef {Object} BaseSinatureParam
 * @property {string} appid - 应用 ID
 * @property {string} secretKey - 应用密钥
 * @property {boolean} [endsWithSecretKey] - 原始字符串末尾是否包含secretKey, 可选, 默认为: false
 */

/**
 * @typedef {Object} BaseRequestParam
 * @property {string} url - 请求 URL
 * @property {string} [method="GET"] - 请求方法（可选，默认值为 GET）
 * @property {string|Object} [body=null] - 请求体（可选，默认值为 null）
 * @property {Object|URLSearchParams} [query=null] - 查询参数对象（可选，默认值为 null）
 */

/**
 * @typedef {Object} BaseGenerateSignatureParam
 * @property {string|number} timestamp - 时间戳, 精确到秒
 * @property {string} nonce - 随机字符串
 * @property {boolean} [endsWithSecretKey=true] - 原始字符串末尾是否包含secretKey, 可选，默认值为 false
 */

/**
 * @typedef {Object} GenerateSignatureParam
 * @property {boolean} [withHashName=true] - 是否包含签名算法名称（可选，默认值为 true）
 * @property {boolean} [pairValue=false] - true - 返回键值对值, false - 返回 `:` 分隔值
 */

/**
 * @typedef {Object} GenerateSignatureResult
 * @property {string} url - 完整的请求URL
 * @property {string} timestamp - 时间戳, 精确到秒
 * @property {string} nonce - 随机字符串
 * @property {string} rawSignatureStr - 原始签名字符串
 * @property {string} signature - 签名结果
 * @property {string} headerValue - 签名请求头值
 */

/**
 * @typedef {Object} GenerateSignatureStrResult
 * @property {string} rawStr - 原始签名字符串
 * @property {string} signature - 签名结果
 */

/**
 * @typedef {Object} BaseVerifySignatureParam
 * @property {boolean} [verifyTimestamp=true] - 是否验证时间戳有效性，防止回放攻击（可选，默认值为 true）
 * @property {number} [timestampValidTime=300] - 时间戳有效时间（可选，默认值为 300 秒）
 */

/**
 * @typedef {Object} VerifySignatureParam
 * @property {string} signature - 签名
 */

/**
 * @typedef {Object} VerifySignatureHeaderParam
 * @property {string|undefined|null} [headerValue] - 签名请求头值
 * @property {boolean} [verifyHashName=true] - 是否包含签名算法名称, 可选，默认值为 true
 * @property {(appid: string) => Promise<string>} getSecretkeyByAppid - 根据 appid 获取 secretKey
 */

/**
 * @typedef {Object} VerifySignatureResult
 * @property {number} code - 是否验证通过, 0 - 验证通过, 1 - 签名错误, 2 - 时间戳错误, 3 - 签名算法错误, 4 - appid 错误
 * @property {string} message - 验证结果描述
 */

/**
 * 生成签名字符串
 * @param {BaseGenerateSignatureParam & BaseSinatureParam & BaseRequestParam} param - 签名配置选项
 * @returns {Promise<GenerateSignatureStrResult>} 返回签名字符串结果对象
 */
export async function generateSignature(param) {
  const m = (param.method || "get").toUpperCase();
  const url = `${param.url}${queryStringify(param.query)}`;
  const signArr = [param.appid, m, url];
  if (m !== "GET" && param.body && param.body !== "{}") {
    const b =
      typeof param.body === "string" ? param.body : JSON.stringify(param.body);
    signArr.push(b);
  }
  signArr.push(param.timestamp, param.nonce);
  if (param.endsWithSecretKey) {
    signArr.push(param.secretKey);
  }
  const signStr = `${signArr.join("\n")}\n`;
  const signature = await hmacHash(signStr, param.secretKey, "SHA-256", true);
  return {
    rawStr: signStr,
    signature,
    url,
  };
}

/**
 * 生成签名信息
 * @param {GenerateSignatureParam & BaseSinatureParam & BaseRequestParam} options - 签名配置选项
 *
 * @example <caption>1. 生成签名</caption>
 * ```js
 * await generateSignature({ appid: "s", url: "/s", secretKey: "d" })
 * ```
 *
 * @example <caption>2. 生成不带算法名称的键值对值的签名</caption>
 * ```js
 * await generateSignature({ appid: "s", url: "/s", secretKey: "d", withHashName: false, pairValue: true })
 * ```
 *
 * @returns {Promise<GenerateSignatureResult>} 返回签名结果对象
 */
export async function generateSignatureHeader(options) {
  const opt = {
    method: "GET",
    pairValue: false,
    withHashName: true,
    ...options,
  };
  const timestamp = `${Math.floor(Date.now() / 1000)}`;
  const nonce = random(8);
  const { rawStr, signature, url } = await generateSignature({
    ...opt,
    timestamp,
    nonce,
  });
  const headerPrefix = opt.withHashName ? "HMAC-SHA256 " : "";
  let headerValue = "";
  if (opt.pairValue) {
    headerValue = `appid=${opt.appid}&timestamp=${timestamp}&nonce=${nonce}&signature=${signature}`;
  } else {
    headerValue = `${opt.appid}:${timestamp}:${nonce}:${signature}`;
  }
  return {
    url,
    timestamp,
    nonce,
    rawStr,
    signature,
    headerValue: `${headerPrefix}${headerValue}`,
  };
}

/**
 * 验证签名
 * @param {BaseSinatureParam & BaseRequestParam & BaseGenerateSignatureParam & BaseVerifySignatureParam & VerifySignatureParam} param - 验签参数
 */
export async function verifySignature(param) {
  const nowTimestamp = Math.floor(Date.now() / 1000);
  if (
    param.verifyTimestamp &&
    nowTimestamp - param.timestamp > param.timestampValidTime
  ) {
    return {
      code: 2,
      message: `timestamp is invalid: ${param.timestamp} - ${nowTimestamp}`,
    };
  }
  const signStr = await generateSignature(param);
  if (signStr.signature === param.signature) {
    return {
      code: 0,
      message: "success",
      appid: param.appid,
      signature: signStr.signature,
    };
  }
  return {
    code: 1,
    message: `signature is invalid: ${param.signature} - ${signStr.signature}(${signStr.rawStr})`,
  };
}

/**
 *
 * @param {BaseVerifySignatureParam & VerifySignatureHeaderParam & GenerateSignatureParam & BaseRequestParam} param
 */
export async function verifySignatureHeader(param) {
  const opts = {
    // 默认配置
    verifyTimestamp: true,
    timestampValidTime: 300,
    verifyHashName: true,
    withHashName: true,
    pairValue: false,
    method: "GET",
    endsWithSecretKey: false,
    ...param,
  };
  let signature = opts.headerValue;
  if (!signature) {
    return {
      code: 1,
      message: "signature is empty",
    };
  }
  if (opts.withHashName) {
    let item = signature.split(" ");
    signature = item[1];
    if (opts.verifyHashName && item[0] !== "HMAC-SHA256") {
      return {
        code: 3,
        message: `hash name is invalid: ${item[0]} - HMAC-SHA256`,
      };
    }
  }
  const sigItem = parseSignatureItem(signature, opts.pairValue);
  const secretKey = await param.getSecretkeyByAppid(sigItem.appid);
  if (!secretKey) {
    return {
      code: 4,
      message: `appid is invalid: ${sigItem.appid}`,
    };
  }
  // 验证签名
  return await verifySignature({
    appid: sigItem.appid,
    secretKey,
    timestamp: sigItem.timestamp,
    nonce: sigItem.nonce,
    url: opts.url,
    method: opts.method,
    body: opts.body,
    query: opts.query,
    signature: sigItem.signature,
    verifyTimestamp: opts.verifyTimestamp,
    timestampValidTime: opts.timestampValidTime,
    endsWithSecretKey: opts.endsWithSecretKey,
  });
}
