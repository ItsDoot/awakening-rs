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

use std::ops::Index;

use clap::{App, Arg};
use log::Level;
use regex::Regex;
use serenity::Client;
use serenity::client::Context;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::prelude::EventHandler;

lazy_static! {
    static ref LOG_SEARCHES: Vec<(Regex, &'static (dyn for<'a> Fn(&'a Context, &'a Message) -> () + std::marker::Sync))> = vec![
        (Regex::new("(java\\.lang\\.NoClassDefFoundError: net/minecraft/world/gen/ChunkProviderServer|java\\.lang\\.NoClassDefFoundError: net/minecraft/world/chunk/BlockStateContainer)").unwrap(), &issue_foamfix)
    ];
}

struct Handler {
    url_regex: Regex,
    http: reqwest::Client,
}

impl EventHandler for Handler {
    fn message(&self, ctx: Context, message: Message) {
        for url_match in self.url_regex.find_iter(&message.content) {
            let url = url_match.as_str();

            let response = self.http.get(url).send()
                .and_then(|mut resp| resp.text())
                .unwrap_or_default();

            for (regex, func) in LOG_SEARCHES.iter() {
                if regex.is_match(response.as_str()) {
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
    let handler = Handler {
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
    static FOAMFIX: &str = "I've detected that your logs contain an error caused by using sponge and foamfix together. \
                            To fix this, disable the following settings by setting them to `false` in `config/foamfix.cfg`:\
                            \n`B:optimizedBlockPos=false`\
                            \n`B:patchChunkSerialization=false`";

    message.reply(&*ctx.http, FOAMFIX);
}