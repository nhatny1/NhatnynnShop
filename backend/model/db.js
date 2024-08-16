const { MongoClient } = require("mongodb");

const url = "mongodb://localhost:27017/";
const dbName = "ASM";

async function connectDb() {
  const client = new MongoClient(url);
  await client.connect();
  console.log("Kết nối thành công đến server");
  return client.db(dbName);
}
module.exports = connectDb;
