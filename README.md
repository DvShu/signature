# Signature

使用 `JS` 封装的一套前后端通用的签名工具，包含：生成签名、验签

## 使用

### 1. 安装

```bash
npm install @asteres/signature
```

### 2. 引入

```js
import {
  generateSignature,
  verifySignature,
  generateSignatureHeader,
  verifySignatureHeader,
} from "@asteres/signature";
```

### 3. 使用

```js
const res = await generateSignature(...);
const res = await verifySignature(...);
```

## API

### 生成签名

1. `generateSignature(): Promise<Result>` 生成签名

2. `generateSignatureHeader(): Promise<Result>` 生成签名并组装为请求头参数

### 验证签名

1. `verifySignature(): Promise<Result>` 验证签名
2. `verifySignatureHeader(): Promise<Result>` 验证签名头参数

## 示例

1. 生成签名

```javascript
generateSignatureHeader({
  appid: '', // APPID
  secretKey: '', SECRET_KEY
  url: '', // 请求地址
  body: '', // 请求体, 可选, 只有在 POST 请求且有body时才传
  query: {}, // URL 参数, 可选
  method: 'GET', // 请求方法
  withHashName: true, // 生成的请求头值是否带上签名算法: HMAC-SHA256
  pairValue: false // 生成的请求头值是 a=1&b=2(true) 形式还是 1:2(false) 形式
})
```

2. 验证签名

```javascript
verifySignatureHeader({
  headerValue: signature, // 获取的签名头的值
  getSecretkeyByAppid: async (appid) => {
    return '';
  }, // 根据appid 获取 secretKey
  verifyTimestamp: true, // 是否验证时间戳, 防止重放攻击
  timestampValidTime: 300, // 验证时间戳时，时间戳有效性：默认: 300s(5min)
  withHashName: true,
  pairValue: false,
  url: '',
  method: '',
  body: '',
  query: {}
});
```

> 如果运行在非安全环境下，无法使用 `window.crypto.subtle` 则需要安装 `crypto-es`; 然后引入到 `window.crypto.HmacSHA256`

```bash
pnpm add crypto-es
```

下面使用 `vite` 做构建工具时

```javascript
import { HmacSHA256 } from "crypto-es";

// 假设 test 环境下不是 https 
if (import.meta.env.MODE === "test") {
  // @ts-ignore
  window.crypto.HmacSHA256 = HmacSHA256;
}

// 然后打包时执行: vite build --mode test
```
