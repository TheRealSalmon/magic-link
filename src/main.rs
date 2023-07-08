use std::sync::Mutex;

use email_address::EmailAddress;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::{
    password_hash::{rand_core::OsRng, SaltString},
    Pbkdf2,
};
use redis::Commands;
use rocket::form::Form;
use rocket::FromForm;
use rocket_dyn_templates::{context, Template};
use sha2::{Digest, Sha256};
use shuttle_secrets::SecretStore;
use std::time::{SystemTime, UNIX_EPOCH};

static URL: &str = "http://127.0.0.1:8000";

#[shuttle_runtime::main]
async fn rocket(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> shuttle_rocket::ShuttleRocket {
    let redis_uri = secret_store.get("REDIS_URI").unwrap();
    let con = redis::Client::open(redis_uri)
        .unwrap()
        .get_connection()
        .unwrap();

    let smtp_password = secret_store.get("SMTP_PASSWORD").unwrap();
    let smtp = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(Credentials::new(
            "rust.test.sam@gmail.com".to_owned(),
            smtp_password,
        ))
        .build();

    let rocket = rocket::build()
        .manage(Mutex::new(con))
        .manage(smtp)
        .mount(
            "/",
            rocket::routes![
                home,
                sign_up,
                register_email,
                validate_email,
                create_account,
                log_in,
            ],
        )
        .attach(Template::fairing());

    Ok(rocket.into())
}

#[rocket::get("/")]
fn home() -> Template {
    Template::render(
        "home",
        context! {
            sign_up_url: format!("{}/sign-up", URL)
        },
    )
}

#[rocket::get("/sign-up")]
fn sign_up() -> Template {
    Template::render("sign-up", context! {})
}

#[rocket::post("/register-email", data = "<user_email>")]
fn register_email(
    user_email: Form<UserEmail>,
    con: &rocket::State<Mutex<redis::Connection>>,
    smtp: &rocket::State<SmtpTransport>,
) -> Template {
    let email = &user_email.email;
    if EmailAddress::is_valid(email) {
        let mut con: std::sync::MutexGuard<'_, redis::Connection> = con.inner().lock().unwrap();
        if con.ttl::<&str, isize>(email).unwrap() == -2 {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();
            let hash = hash_string(&(email.clone() + &current_time));
            let email_body = format!("Welcome to magic link!\n\nIf you didn't sign up, ignore this email.\n\nRegistration link: {}/validate-email/{}", URL, hash);
            send_email(email, &email_body, smtp.inner()).unwrap();
            let _: () = con.set_ex(email, &hash, 86400).unwrap();
            let _: () = con.set_ex(&hash, email, 86400).unwrap();
            Template::render(
                "register-email",
                context! {
                    message: format!("validation email sent to {}", email),
                },
            )
        } else {
            Template::render(
                "error",
                context! {
                    error: format!("{} is already registered", email),
                },
            )
        }
    } else {
        Template::render(
            "error",
            context! {
                error: format!("{} is not a valid email", email),
            },
        )
    }
}

#[rocket::get("/validate-email/<hash>")]
fn validate_email(hash: String, con: &rocket::State<Mutex<redis::Connection>>) -> Template {
    let mut con: std::sync::MutexGuard<'_, redis::Connection> = con.inner().lock().unwrap();
    if let Ok(email) = con.get::<&str, String>(&hash) {
        let _: () = con.del(&hash).unwrap();
        Template::render(
            "validate-email",
            context! {
                email: email,
            },
        )
    } else {
        Template::render(
            "error",
            context! {
                error: format!("register your email here first, {}/sign-up", URL),
            },
        )
    }
}

#[rocket::post("/create-account", data = "<user_account>")]
fn create_account(
    user_account: Form<UserAccount>,
    con: &rocket::State<Mutex<redis::Connection>>,
) -> Template {
    let mut con: std::sync::MutexGuard<'_, redis::Connection> = con.inner().lock().unwrap();
    match con.ttl::<&str, isize>(&user_account.email).unwrap() {
        -2 => Template::render(
            "error",
            context! {
                error: format!("register your email here first, {}/sign-up", URL),
            },
        ),
        -1 => Template::render(
            "error",
            context! {
                error: format!("account already exists"),
            },
        ),
        _ => {
            let _: () = con
                .set(&user_account.email, hash_password(&user_account.password))
                .unwrap();
            Template::render("log-in", context! {})
        }
    }
}

#[rocket::get("/log-in")]
fn log_in() -> Template {
    Template::render("log-in", context! {})
}

#[derive(FromForm)]
struct UserEmail {
    email: String,
}

#[derive(FromForm)]
struct UserAccount {
    email: String,
    password: String,
}

fn hash_string(string: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(string);
    format!("{:x}", hasher.finalize())
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Pbkdf2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn send_email(recipient: &str, email_body: &str, smtp: &SmtpTransport) -> Result<(), ()> {
    let message = Message::builder()
        .from(format!("rust-test-sam <{}>", recipient).parse().unwrap())
        .to(format!("<{}>", recipient).parse().unwrap())
        .subject("Magic Link")
        .header(ContentType::TEXT_PLAIN)
        .body(email_body.to_owned())
        .unwrap();

    match smtp.send(&message) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}
