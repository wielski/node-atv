import fs from "fs";
import { main } from "../src/cmd/pair";

if (!process.argv[2]) {
    throw new Error(`Please set udid: ${process.argv[0]} xxx-xxx-xxx-xxx "Living Room"`);
}

if (!process.argv[3]) {
    throw new Error(`Please set device name: ${process.argv[0]} xxx-xxx-xxx-xxx "Living Room"`);
}

const udid = process.argv[2];
const name = process.argv[3];

main(udid, name).then((connection) => {
    fs.writeFileSync(`${udid}.connection`, connection.toString());
    process.exit(0);
}).catch((e) => {
    console.error(e);
    process.exit(1);
});
