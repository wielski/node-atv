import fs from "fs";
import { main } from "../cmd/install";
import { Credentials } from "../models/credentials";

if (!process.argv[2]) {
    throw new Error(`Please set device udid: ${process.argv[0]} xxx-xxx-xxx-xxx /path/to/app.ipa`);
}

if (!process.argv[3]) {
    throw new Error(`Please set ipa path: ${process.argv[0]} xxx-xxx-xxx-xxx /path/to/app.ipa`);
}

const udid = process.argv[2];
const ipa = process.argv[3];

const credentialsContent = fs.readFileSync(`${udid}.connection`);
const credentials = Credentials.fromString(credentialsContent.toString());

main(credentials, udid, ipa).then((bundleId) => {
    console.log(`App ${bundleId} installed!`);
}).catch((e) => {
    console.error(e);
    process.exit(1);
});
