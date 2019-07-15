#![feature(fn_traits)]

extern crate clap;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate regex;
extern crate reqwest;
#[macro_use]
extern crate serenity;
extern crate simple_logger;

use std::sync::Arc;

use clap::{App, Arg};
use log::Level;
use regex::Regex;
use serenity::Client;
use serenity::client::Context;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::prelude::EventHandler;

static SITE_WHITELIST: &[&str] = &[
    "http://paste.gg/",
    "http://paste.ee/",
    "http://paste.feed-the-beast.com/",
    "http://pastebin.com/",
    "http://hastebin.com/",
    "http://gist.github.com/",
    "https://paste.gg/",
    "https://paste.ee/",
    "https://paste.feed-the-beast.com/",
    "https://pastebin.com/",
    "https://hastebin.com/",
    "https://gist.github.com/",
];

type LogSearchHandler = &'static (dyn for<'a> Fn(&'a Context, &'a Message) -> () + Sync);
type RegexExecutor = (Regex, LogSearchHandler);

struct Handler {
    log_searches: Arc<Vec<RegexExecutor>>,
    url_regex: Regex,
    http: reqwest::Client,
}

impl EventHandler for Handler {
    fn message(&self, ctx: Context, message: Message) {
        for url in self.url_regex.find_iter(&message.content)
            .map(|x| x.as_str())
            .filter(|x| SITE_WHITELIST.iter().any(|site| x.starts_with(site)))
            .take(5) {

            let response = self.http.get(url).send()
                .and_then(|mut resp| resp.text())
                .unwrap_or_default();

            for (regex, func) in self.log_searches.iter() {
                if regex.is_match(&response) {
                    func.call((&ctx, &message));
                }
            }
        }
    }

    fn ready(&self, _ctx: Context, ready: Ready) {
        info!("Logged in as {}#{}", ready.user.name, ready.user.discriminator);
    }
}

fn main() {
    let mut log_searches: Vec<RegexExecutor> = Vec::new();

    log_searches.push(
        (
            exact_parts(&[
                "java.lang.NoClassDefFoundError: net/minecraft/world/gen/ChunkProviderServer",
                "java.lang.NoClassDefFoundError: net/minecraft/world/chunk/BlockStateContainer",
            ]),
            &issue_foamfix
        )
    );
    log_searches.push(
        (
            escaped("syscall:writev(..) failed: Broken pipe"),
            &issue_broken_pipe
        )
    );
    log_searches.push(
        (
            Regex::new("Mixin config \\w+\\.json requires mixin subsystem version 0\\.7\\.\\d but 0\\.7\\.\\d was found\\. The mixin config will not be applied\\.").unwrap(),
            &issue_old_mixin
        )
    );

    let handler = Handler {
        log_searches: Arc::new(log_searches),
        url_regex: Regex::new("https?://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]").unwrap(),
        http: reqwest::Client::new(),
    };

    simple_logger::init_with_level(Level::Info).unwrap();

    let matches = App::new("Awakening")
        .version("0.1.0")
        .author("doot <xdotdash@gmail.com>")
        .about("A discord bot.")
        .arg(Arg::with_name("token")
            .help("Sets the discord bot token")
            .value_name("TOKEN")
            .required(true)
            .index(1))
        .get_matches();

    let token = matches.value_of("token").unwrap();

    let mut client = Client::new(token, handler).expect("failed to create discord client");

    client.start();
}

fn issue_foamfix(ctx: &Context, message: &Message) {
    static FOAMFIX: &str =
        "I've detected that your logs contain an error caused by using Sponge and FoamFix together. \
         To fix this, disable the following settings by setting them to `false` in `config/foamfix.cfg`:\
         \n`B:optimizedBlockPos=false`\
         \n`B:patchChunkSerialization=false`";

    message.reply(&*ctx.http, FOAMFIX);
}

fn issue_broken_pipe(ctx: &Context, message: &Message) {
    static BROKEN_PIPE: &str =
        "I've detected that your logs contain an error caused by an outdated netty version. \
         Read here to see how to update it: <https://gist.github.com/phit/be5b69b76217bb8bab7b1cd752d4c39e>";

    message.reply(&*ctx.http, BROKEN_PIPE);
}

fn issue_old_mixin(ctx: &Context, message: &Message) {
    static OLD_MIXIN: &str =
        "I've detected that your logs contain an error caused by loading an outdated Mixin version before Sponge, please report it to the mod author! \
         For a temporary solution, rename the SpongeForge jar file so that it's sorted alphabetically before all other mods \
         (for example: `spongeforge-1.12.2-2825-7.1.6.jar` -> `_aspongeforge-1.12.2-2825-7.1.6.jar`)";

    message.reply(&*ctx.http, OLD_MIXIN);
}

fn exact_parts(parts: &[&str]) -> Regex {
    let mut result = String::new();
    result.push('(');
    result.push_str(&parts.iter().map(|&x| regex::escape(x)).collect::<Vec<String>>().join("|"));
    result.push(')');
    Regex::new(&result).unwrap()
}

#[inline(always)]
fn escaped(text: &str) -> Regex {
    Regex::new(&regex::escape(text)).unwrap()
}