import { Client, Intents, MessageEmbed } from "discord.js";
import { MessageTypes } from "discord.js/typings/enums";
import { readFileSync } from "fs";
import { JsonDB } from 'node-json-db';
import { Config } from 'node-json-db/dist/lib/JsonDBConfig'
const token = readFileSync("token.txt");
const db = new JsonDB(new Config("db", true, false, ":"));
const bot = new Client({intents: [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MEMBERS, Intents.FLAGS.GUILD_MESSAGES]});
const prefix = "~!";

// this variable is licensed MIT from Diego Perini
const re_weburl = new RegExp(
    "\b" +
      // protocol identifier (optional)
      // short syntax // still required
      "(?:(?:(?:https?|ftp):)?\\/\\/)" +
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
      ")" +
      // port number (optional)
      "(?::\\d{2,5})?" +
      // resource path (optional)
      "(?:[/?#]\\S*)?" +
    "\b", "ig"
  );

bot.on("messageCreate", (msg) => {
    if (msg.guild) {
        if (db.exists(`honeypots:${msg.guildId}`)) {
            if (msg.channelId == db.getData(`honeypots:${msg.guildId}`)) {
                const urls = [...msg.content.matchAll(re_weburl)];
                console.log(urls);
                // TODO: delete this user's messages; actually do stuff with urls
                msg.channel.send({content: "TODO: delete this user's messages; actually do stuff with urls", embeds: [new MessageEmbed().setDescription(`Detected URLS: \n${urls.join("\n")}`)]});
            }
        }
        //TODO: delete any message that already contains a detected link.
    }
});

bot.on("interactionCreate", (int) => {
    if (int.isCommand()) {
        if (int.commandName == "report") {
            const urls = [...int.options.getString("urls")?.matchAll(re_weburl) ?? []];
            console.log(urls);
            // TODO: figure out how to get user command is "replying" to
            // TODO: delete replied to user's messages (if reply); actually do stuff with urls
            int.reply({content: "TODO: delete replied to user's messages; actually do stuff with urls", embeds: [new MessageEmbed().setDescription(`Detected URLS: \n${urls.join("\n")}`)]});
        } else if (int.commandName == "honeypot") {
            const channel = int.options.getChannel("channel");
            db.push(`honeypots:${int.guild?.id}`, channel?.id);
            int.reply({embeds: [new MessageEmbed().setTitle("HoneyPot Channel:").setDescription(channel?.toString() ?? "bad channel")]});
        }
    }

});

bot.login(token.toString());

