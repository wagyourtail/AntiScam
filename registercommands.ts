import { REST } from "@discordjs/rest";
import { SlashCommandBuilder, SlashCommandChannelOption, SlashCommandStringOption } from "@discordjs/builders";
import { ChannelType, Routes } from "discord-api-types/v9";
import { readFileSync } from "fs";
const token = readFileSync("token.txt").toString().trim();
const clientid = "902970889178583121";
const commands = [
    new SlashCommandBuilder().setName("report").setDescription("reports site linked or site linked in message you're replying to as a phishing site.").addStringOption(new SlashCommandStringOption().setName("urls").setDescription("url or list of urls (space seperated)").setRequired(true)),
    new SlashCommandBuilder().setName("honeypot").setDescription("sets a honeypot channel where all messages with links are reported and deleted.").addChannelOption(new SlashCommandChannelOption().addChannelType(ChannelType.GuildText).setName("channel").setDescription("channel to watch").setRequired(true)),
    new SlashCommandBuilder().setName("invite").setDescription("get a discord invite link")
];

const rest = new REST({ version: '9' }).setToken(token);
rest.put(Routes.applicationCommands(clientid), { body: commands })
	.then(() => console.log('Successfully registered application commands.'))
	.catch(console.error);