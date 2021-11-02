import {Mutex} from "async-mutex";
import {Client, Intents, MessageEmbed} from "discord.js";
import {MessageTypes} from "discord.js/typings/enums";
import {existsSync, readFileSync, writeFileSync} from "fs";

const token = readFileSync("token.txt");
const bot = new Client({intents: [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MEMBERS, Intents.FLAGS.GUILD_MESSAGES]});
const prefix = "~!";

class JsonDB {
    readonly readMutex = new Mutex();
    readonly writeMutex = new Mutex();
    readonly file;
    readonly sep;
    json: any;

    constructor(id: string, sep: string) {
        this.sep = sep;
        this.file = `${id}.json`;
        if (existsSync(this.file)) {
            this.json = JSON.parse(readFileSync(this.file).toString());
        } else {
            this.json = {};
        }
    }

    async acquireWrite() {
        const releaseRead = await this.readMutex.acquire();
        const releaseWrite = await this.writeMutex.acquire();
        return () => {
            releaseRead();
            releaseWrite();
        }
    }

    async acquireRead() {
        return await this.readMutex.acquire();
    }

    async updateValue<T>(key: string, updater: (old: T | undefined) => T) {
        const release = await this.acquireWrite();
        try {
            const parts = key.split(this.sep);
            let ptr = this.json;
            for (const part of parts) {
                if (!(part in ptr)) ptr[part] = {};
                ptr = ptr[part];
            }
            ptr["value"] = updater(ptr["value"])
            writeFileSync(this.file, JSON.stringify(this.json));
        } finally {
            release();
        }
    }

    async getValue<T>(key: string): Promise<T> {
        const release = await this.acquireRead();
        try {
            const parts = key.split(this.sep);
            let ptr = this.json;
            for (const part of parts) {
                if (!(part in ptr)) ptr[part] = {};
                ptr = ptr[part];
            }
            return ptr["value"];
        } finally {
            release();
        }
    }
}

const db = new JsonDB("db", ":");


// this variable is licensed MIT from Diego Perini
const re_weburl = new RegExp(
    "" +
    // protocol identifier (optional)
    // short syntax // still required
    "((?:(?:(?:https?|hxxps?):)?\\/\\/)" +
    // user:pass BasicAuth (optional)
    "(?:\\S+(?::\\S*)?@)?" +
    "(?:" +
    // IP address exclusion
    // private & local networks
    "(?!(?:10|127)(?:\\.\\d{1,3}){3})" +
    "(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})" +
    "(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})" +
    // IP address dotted notation octets
    // excludes loopback network 0.0.0.0
    // excludes reserved space >= 224.0.0.0
    // excludes network & broadcast addresses
    // (first & last IP address of each class)
    "(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])" +
    "(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}" +
    "(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))" +
    "|" +
    // host & domain names, may end with dot
    // can be replaced by a shortest alternative
    // (?![-_])(?:[-\\w\\u00a1-\\uffff]{0,63}[^-_]\\.)+
    "(?:" +
    "(?:" +
    "[a-z0-9\\u00a1-\\uffff]" +
    "[a-z0-9\\u00a1-\\uffff_-]{0,62}" +
    ")?" +
    "[a-z0-9\\u00a1-\\uffff]\\." +
    ")+" +
    // TLD identifier name, may end with dot
    "(?:[a-z\\u00a1-\\uffff]{2,}\\.?)" +
    "))" +
    // port number (optional)
    "(?::\\d{2,5})?" +
    // resource path (optional)
    "(?:[/?#]\\S*)?" +
    "", "ig"
);


bot.on("messageCreate", async (msg) => {
    if (msg.guild) {
        const urls: string[] = [...msg.content.matchAll(re_weburl)].map(e => e[1].replace(/^h[xt]{2}ps?:\/\//, ""));
        const hp: string | undefined = await db.getValue(`honeypots:${msg.guildId}`);
        if (msg.channelId == hp) {
            if (urls.length) {
                // TODO: delete this user's messages
                // ban the user then unban to delete their recent messages easier
                await msg.member?.ban({days: 1, reason: "honeypot triggered"});
                await msg.guild.bans.remove(msg.author);
                await db.updateValue<any>("urls", (obj) => {
                    for (const url of urls) {
                        if (!obj) obj = {};
                        obj[url] = (obj[url] ?? 0) - 1;
                        return obj;
                    }
                });
            }
        } else {
            console.log(urls);
            // delete any message that already contains a detected link.
            const known: {[url: string]: number} = await db.getValue("urls");
            console.log(known);
            for (const url of urls) {
                if (url in known) {
                    if (known[url] < 0) {
                        await msg.delete();
                        break;
                    }
                }
            }
        }
    }
});

bot.on("interactionCreate", async (int) => {
    if (int.isCommand()) {
        if (int.commandName == "report") {
            const urls: string[] = [...int.options.getString("urls")?.matchAll(re_weburl) ?? []].map(e => e[1].replace(/^h[xt]{2}ps?:\/\//, ""));
            // TODO: figure out how to get user command is "replying" to
            // TODO: delete replied to user's messages (if reply)
            await int.reply({embeds: [new MessageEmbed().setDescription(`Detected URLS: \n${urls.join("\n")}`)]});
            await db.updateValue<any>("urls", (obj) => {
                for (const url of urls) {
                    if (!obj) obj = {};
                    obj[url] = (obj[url] ?? 0) - 1;
                    return obj;
                }
            });
        } else if (int.commandName == "honeypot") {
            const channel = int.options.getChannel("channel");
            await db.updateValue(`honeypots:${int.guild?.id}`, () => channel?.id);
            await int.reply({embeds: [new MessageEmbed().setTitle("HoneyPot Channel:").setDescription(channel?.toString() ?? "bad channel")]});
        }
    }

});

bot.login(token.toString());

//TODO upload urls to pastebin on a timer