import * as Minio from "minio";

const globalForMinio = globalThis as unknown as {
  minioClient: Minio.Client | undefined;
};

function minioEndPoint(): string {
  const ep = process.env.MINIO_ENDPOINT || "127.0.0.1";
  return ep === "localhost" ? "127.0.0.1" : ep;
}

export const minioClient =
  globalForMinio.minioClient ??
  new Minio.Client({
    endPoint: minioEndPoint(),
    port: parseInt(process.env.MINIO_PORT || "9000"),
    useSSL: process.env.MINIO_USE_SSL === "true",
    accessKey: process.env.MINIO_ACCESS_KEY || "minioadmin",
    secretKey: process.env.MINIO_SECRET_KEY || "minioadmin",
  });

if (process.env.NODE_ENV !== "production")
  globalForMinio.minioClient = minioClient;

const BUCKET = process.env.MINIO_BUCKET || "pepper-artifacts";

export async function ensureBucket() {
  const exists = await minioClient.bucketExists(BUCKET);
  if (!exists) {
    await minioClient.makeBucket(BUCKET);
  }
}

export async function uploadObject(
  key: string,
  data: Buffer | string,
  contentType = "application/octet-stream",
): Promise<void> {
  const buffer = typeof data === "string" ? Buffer.from(data) : data;
  await minioClient.putObject(BUCKET, key, buffer, buffer.length, {
    "Content-Type": contentType,
  });
}

export async function downloadObject(key: string): Promise<Buffer> {
  const stream = await minioClient.getObject(BUCKET, key);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

export async function getPresignedUrl(
  key: string,
  expiry = 3600,
): Promise<string> {
  return minioClient.presignedGetObject(BUCKET, key, expiry);
}

export async function deleteObject(key: string): Promise<void> {
  await minioClient.removeObject(BUCKET, key);
}

export { BUCKET };
