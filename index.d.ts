type BaseSinatureParam = {
  /** 应用 ID */
  appid: string;
  /** 应用密钥 */
  secretKey: string;
  /** 原始字符串末尾是否包含secretKey, 可选, 默认为: false */
  endsWithSecretKey?: boolean;
};

type BaseRequestParam = {
  /** 请求地址 */
  url: string;
  /** 请求方法（可选，默认值为 GET） */
  method?: string;
  /** 请求体（可选，默认值为 null） */
  body?: string | object | null | undefined;
  /** 查询参数对象（可选，默认值为 null） */
  query?: object | URLSearchParams | string;
};

type BaseGenerateSignatureParam = {
  /** 时间戳, 精确到秒 */
  timestamp?: number | string;
  /** 随机字符串 */
  nonce?: string;
};

type BaseGenerateSignatureHeaderParam = {
  /** 是否包含签名算法名称（可选，默认值为 true） */
  withHashName?: boolean;
  /** true - 返回键值对值, false - 返回 `:` 分隔值 */
  pairValue?: boolean;
};

type GenerateSignatureResult = {
  /** 完整的请求URL */
  url: string;
  /** 时间戳, 精确到秒 */
  timestamp: string;
  /** 随机字符串 */
  nonce: string;
  /** 原始签名字符串 */
  rawSignatureStr: string;
  /** 签名结果 */
  signature: string;
  /** 签名请求头值 */
  headerValue: string;
};

type GenerateSignatureStrResult = {
  /** 原始签名字符串 */
  rawStr: string;
  /** 签名结果 */
  signature: string;
};

type BaseVerifySignatureParam = {
  /** 是否验证时间戳有效性，防止回放攻击（可选，默认值为 true） */
  verifyTimestamp?: boolean;
  /** 时间戳有效时间（可选，默认值为 300 秒） */
  timestampValidTime?: number;
};

type VerifySignatureParam = BaseSinatureParam &
  BaseRequestParam &
  BaseGenerateSignatureParam &
  BaseVerifySignatureParam & {
    /** 签名 */
    signature: string;
  };

type VerifySignatureHeaderParam = BaseVerifySignatureParam &
  BaseGenerateSignatureHeaderParam &
  BaseRequestParam & {
    /** 签名请求头值 */
    headerValue?: string | undefined | null;
    /** 是否包含签名算法名称, 可选，默认值为 true */
    verifyHashName?: boolean;
    /** 根据 appid 获取 secretKey */
    getSecretkeyByAppid: (appid: string) => Promise<string>;
  };

type VerifySignatureResult = {
  /** 是否验证通过, 0 - 验证通过, 1 - 签名错误, 2 - 时间戳错误, 3 - 签名算法错误 */
  code: number;
  /** 验证结果描述 */
  message: string;
  appid: string;
  signature: string;
};

type GenerateSignatureParam = BaseGenerateSignatureParam &
  BaseSinatureParam &
  BaseRequestParam;

type GenerateSignatureHeaderParam = GenerateSignatureParam &
  BaseGenerateSignatureHeaderParam;

/**
 * 生成签名字符串
 * @param param - 签名参数对象
 * @returns Promise<GenerateSignatureStrResult> 返回签名结果
 */
export function generateSignature(
  param: GenerateSignatureParam
): Promise<GenerateSignatureStrResult>;

/**
 * 生成签名信息
 * @param param - 签名配置选项
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
 * @returns 返回签名结果对象
 */
export function generateSignatureHeader(
  param: GenerateSignatureHeaderParam
): Promise<GenerateSignatureResult>;

/**
 * 验证签名
 * @param param - 验签参数
 */
export function verifySignature(
  param: VerifySignatureParam
): Promise<VerifySignatureResult>;

/**
 * 验证签名头
 * @param param - 验签名头参数
 */
export function verifySignatureHeader(
  param: VerifySignatureHeaderParam
): Promise<VerifySignatureResult>;
