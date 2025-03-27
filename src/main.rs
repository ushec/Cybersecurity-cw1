use std::error::Error;

use iced::alignment::Horizontal;
use iced::futures::TryFutureExt;
use iced::widget::{button, checkbox, column, container, row, text, text_input};
use iced::{Element, Size, Task};

use reqwest::Client;
use sha1::{Digest, Sha1};

#[derive(Clone, Copy, Debug)]
pub struct BreachResult {
    sites: usize,
    ocurances: u64,
}

impl BreachResult {
    pub fn new(input: &str, hash: &str) -> Self {
        let entries: Vec<_> = parse_results(input)
            .into_iter()
            .filter(|(hash_suffix, _)| *hash_suffix == &hash[5..])
            .collect();

        let ocurances = entries.iter().map(|(_, count)| count).sum();

        Self {
            sites: entries.len(),
            ocurances,
        }
    }
}

#[derive(Default, Debug)]
enum SearchResult {
    Breaches(BreachResult),
    Errored(String),

    #[default]
    NotSubmitted,
    Searching,
}

#[derive(Debug, Clone)]
pub enum Message {
    Input(String),
    Submit,
    BreachResult(Result<BreachResult, String>),
    ShowPassword(bool),
}

#[derive(Debug, Default)]
pub struct App {
    password: String,
    current_hash: String,
    show: bool,
    state: SearchResult,
}

impl App {
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Input(input) => {
                self.password = input;
                self.current_hash = hash_password(&self.password);
                self.state = SearchResult::NotSubmitted;
            }

            Message::Submit => {
                self.state = SearchResult::Searching;
                let hash = hash_password(&self.password);
                return Task::future(search(hash).map_err(|e| e.to_string()))
                    .map(Message::BreachResult);
            }
            Message::BreachResult(breach_result) => match breach_result {
                Ok(breach) => self.state = SearchResult::Breaches(breach),
                Err(error) => self.state = SearchResult::Errored(error),
            },
            Message::ShowPassword(show) => self.show = show,
        }

        Task::none()
    }

    pub fn view(&self) -> Element<Message> {
        let password_not_empty = !self.password.is_empty();
        let title = text("Is this password in a data breach?").size(27);
        let message = match &self.state {
            SearchResult::Breaches(breaches) => {
                if breaches.sites == 0 {
                    text!("No breaches using this password! It seems this password is safe to use.")
                        .style(text::success)
                } else {
                    text!("This password has been found {} time(s) across {} website(s)\nYou should not use this password!", breaches.ocurances, breaches.sites).style(text::danger)
                }
            }
            SearchResult::Errored(error) => text!("Error: {}", error).style(text::danger),
            SearchResult::NotSubmitted => text!(""),
            SearchResult::Searching => text!("Searching...").style(text::secondary),
        };
        let content = column![
            text!("SHA-1: {}", &self.current_hash),
            row![
                text_input("input password", &self.password)
                    .secure(!self.show)
                    .on_input(Message::Input)
                    .on_submit_maybe(password_not_empty.then_some(Message::Submit)),
                button("Submit").on_press_maybe(password_not_empty.then_some(Message::Submit))
            ]
            .spacing(5),
            checkbox("Show Password", self.show).on_toggle(Message::ShowPassword),
            message,
        ]
        .padding(10)
        .spacing(5);
        container(column![title, content].align_x(Horizontal::Center)).into()
    }
}

pub fn hash_password(pass: &str) -> String {
    if pass.is_empty() {
        return "".into();
    }

    let mut hasher = Sha1::new();
    hasher.update(pass.as_bytes());
    let hash = hasher.finalize();

    format!("{:X}", hash)
}

fn parse_results(input: &str) -> Vec<(&str, u64)> {
    input
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter_map(|(in_hash, count)| Some((in_hash, u64::from_str_radix(count, 10).ok()?)))
        .collect()
}

async fn search(hash: String) -> Result<BreachResult, Box<dyn Error>> {
    let client = Client::new();
    let response = client
        .get(format!(
            "https://api.pwnedpasswords.com/range/{}",
            &hash[..5]
        ))
        .send()
        .await?;
    let body = response.text().await?;

    Ok(BreachResult::new(&body, &hash))
}

fn main() -> iced::Result {
    iced::application("Password databreach checker", App::update, App::view)
        .theme(|_| iced::Theme::CatppuccinMacchiato)
        .window_size(Size::new(640., 480.))
        .run()
}
