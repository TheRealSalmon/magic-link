use email_address::EmailAddress;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rocket::response::status;
use rocket_db_pools::deadpool_redis::redis::AsyncCommands;
use rocket_db_pools::{Connection, Database, deadpool_redis};
use sha2::{Sha512, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Database)]
#[database("redis_pool")]
struct RedisPool(deadpool_redis::Pool);

#[rocket::launch]
fn rocket() -> _ {
    let credentials: toml::Value = include_str!("../.credentials").parse().unwrap();
    let email = credentials["email"].as_str().unwrap().trim_matches('"').to_owned();
    let password = credentials["smtp-password"].as_str().unwrap().trim_matches('"').to_owned();
    let credentials = Credentials::new(email.to_owned(), password);

    rocket::build()
        .manage(credentials)
        .attach(RedisPool::init())
        .mount("/", rocket::routes![index, register_email])
}

#[rocket::get("/")]
fn index() -> String {
    "Hello world".to_owned()
}

#[rocket::get("/register-email/<email>")]
async fn register_email(email: String, mut db: Connection<RedisPool>, smtp_creds: &rocket::State<Credentials>) -> Result<String, status::BadRequest<String>> {
    if EmailAddress::is_valid(&email) {
        let db = &mut *db;
        if !db.exists::<&str, bool>(&email).await.unwrap() {
            let hash = hash_strings_to_string(&[&email, &SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string()]);
            let email_body = format!("Welcome to magic link!\n\nIf you didn't sign up, ignore this email.\n\nRegistration link: http://127.0.0.1:8000/validate-email/{}", hash);
            match send_email(&email, &email_body, smtp_creds.inner().clone()).await {
                Ok(_) => {
                    db.set_ex::<&str, &str, bool>(&email, &hash, 86400).await.unwrap();
                    db.set_ex::<&str, &str, bool>(&hash, &email, 86400).await.unwrap();
                    Ok(format!("registration email was sent to {}", email))
                },
                Err(_) => {
                    Err(status::BadRequest(Some(format!("registration link couldn't be sent to {}", email))))
                }
            }
        } else {
            Err(status::BadRequest(Some(format!("email {} already exists", email))))
        }
    } else {
        Err(status::BadRequest(Some(format!("invalid email {}", email))))
    }
}

#[rocket::get("/validate-email/<hash>")]
async fn validate_email(hash: String, mut db: Connection<RedisPool>) -> Result<String, status::BadRequest<String>> {
    Ok("".to_owned())
}

fn hash_string_to_string(string: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(string);
    format!("{:x}", hasher.finalize())
}

fn hash_strings_to_string(strings: &[&str]) -> String {
    let mut hasher = Sha512::new();
    for string in strings {
        hasher.update(string);
    }
    format!("{:x}", hasher.finalize())
}

async fn send_email(recipient: &str, email_body: &str, smtp_creds: Credentials) -> Result<(), ()> {
    let message = Message::builder()
        .from(format!("rust-test-sam <{}>", recipient).parse().unwrap())
        .to(format!("<{}>", recipient).parse().unwrap())
        .subject("Magic Link")
        .header(ContentType::TEXT_PLAIN)
        .body(email_body.to_owned())
        .unwrap();

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(smtp_creds)
        .build();

    match mailer.send(&message) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}
