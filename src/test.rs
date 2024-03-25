use std::sync::Arc;

use super::*;
#[cfg(feature = "async")]
use crate::client::GoogleSigninTokioClient;
use crate::error::Error;
use crate::jwk::JsonWebKey;
use crate::jwk::JsonWebKeySet;
#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::KeyProvider;
use crate::{error::TokenValidationError, token::GoogleSigninClaimsError};
#[cfg(feature = "async")]
use futures::future::join_all;

#[cfg(feature = "async")]
use async_trait::async_trait;

const TOKEN: &'static str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE3NDhlOWY3NjcxNTlmNjY3YTAyMjMzMThkZTBiMjMyOWU1NDQzNjIifQ.eyJhenAiOiIzNzc3MjExNzQwOC1xanFvOWhjYTUxM3BkY3VudW10N2drMDhpaTZ0ZThpcy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjM3NzcyMTE3NDA4LXFqcW85aGNhNTEzcGRjdW51bXQ3Z2swOGlpNnRlOGlzLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA3MDY3MzYxNTAzOTU0NDc0NDg4IiwiZW1haWwiOiJmdWNoc25qQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiaTBOWk5kYWp3UklJbDJvUk9zUUptUSIsImV4cCI6MTUyNjQ5MjUzMywiaXNzIjoiYWNjb3VudHMuZ29vZ2xlLmNvbSIsImp0aSI6IjNmMjc1YjRiY2JmZDU0Y2IxNjZmMzcxNWQ1NTBkMWNmMmUxYThiZGEiLCJpYXQiOjE1MjY0ODg5MzMsIm5hbWUiOiJOYXRoYW4gRm94IiwicGljdHVyZSI6Imh0dHBzOi8vbGg1Lmdvb2dsZXVzZXJjb250ZW50LmNvbS8tbEJSLWE3Z2gwdFkvQUFBQUFBQUFBQUkvQUFBQUFBQUFFUk0vNDFHUk43cDNNVzQvczk2LWMvcGhvdG8uanBnIiwiZ2l2ZW5fbmFtZSI6Ik5hdGhhbiIsImZhbWlseV9uYW1lIjoiRm94IiwibG9jYWxlIjoiZW4ifQ.pOoIMLZgZIFP-fgQirCRRK31ap_CO7WZDeHge-U5GoAvF0VdkoSDSL-1-8d93qKb8IWzi2iS2MgaLekcX8eELM5x39Th1sBwjQGjYr5AXmqE53WDQiqvKzrz-BZ3ay0uSAMllxWfFi62BkSP3m1HJNWyUWrUf6GyI-Vy024dtrX9Qq_BOznJWbQVhHf5aA7x5AAoLHZ_PmzxbUlDQ7Go6FD7sgkoksZI4Cp77HZJMXXGVOrvvXJkpctTcuBZ2P-2filLmb29JIm0e4McOjeHQTV7XNGdzTZoyeSZcU5xTVFQK89e-SIPHKyaL7TAr_faBbTGzVryYfa2VFyKi7Z9gA";
const JWKS: &'static str = r#"{
 "keys": [
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "3f3ef9c7803cd0b8d75247ee0d31fdd5c2cf3812",
   "n": "xM3ZHCgrJLe8y0rBZUWHOS1pCpJ2PjM_gw0WI9D0rljoZ7zWQpEC5UwpWaJqqDKxokt-kKP9GYXILqEsZrQ86qXvRZDPrP39RUjMl3Yl0hE4PlTx3aXuSE8SYqy506yduKjHw3seQHBiqSkVdLXSXqsEKUUrtFEgUxwL5L0yU4N3uJcAWK-oka8RxQSFJEilX5UOH-Qmz4UEeIr7Ma8cdsjibUc6xC9SRJtblmAdDDA_-1aMAJuYH8tGYnpTftwKbaaD0btq0LIzrsFnLu2--jaBul4u0k0jukolnUP0XSqE6NEc0iHTCdbKHZN6LrKVZoUqncTAS7Qa6TbgN1-lHw",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "a748e9f767159f667a0223318de0b2329e544362",
   "n": "tuhr2NvyeXM215R3uvFHL040vM_jQvynwALBRCO0GPy4TxicZmmIEr3nxRsv7c2KNTQUltaiImSocdUwCczQYtCokb9TIx225hqoD-3Mr6dmqkicMcdjqVgjShRzgcHX7c1ipi9r7YvePdOyQutr-SrT9qHFbC5B5CGrY5J3VsEq6wNVeFwto9utMbn7YmENMJp5ws3O3p7YkSrRAxdhzVefciUWD3E6PZrDlcNBUVjKX1lTWfpcfKAUVqUT0Kf2_A1QCqMr1Sjsj8PGeAMtslsK1N59QhwCAarNaEW1H02iFqSalJpgSlw-wN6XMyc1wnIBpstJrjnFwvN0jTe34w",
   "e": "AQAB"
  }
 ]
}"#;
const AUDIENCE: &'static str =
    "37772117408-qjqo9hca513pdcunumt7gk08ii6te8is.apps.googleusercontent.com";
const EMAIL: &'static str = "fuchsnj@gmail.com";
const KIDS: [&str; 2] = [
    "3f3ef9c7803cd0b8d75247ee0d31fdd5c2cf3812",
    "a748e9f767159f667a0223318de0b2329e544362",
];
const AFTER_EXPIRATION: u64 = 2000000000;

#[derive(Default)]
struct TestKeyProvider {
    call_count: Arc<std::sync::RwLock<u8>>,
}

#[cfg(feature = "blocking")]
impl KeyProvider for TestKeyProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        let set: JsonWebKeySet = serde_json::from_str(JWKS).unwrap();
        *self.call_count.write().unwrap() += 1;
        Ok(set.get_key(key_id))
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncKeyProvider for TestKeyProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        let set: JsonWebKeySet = serde_json::from_str(JWKS).unwrap();
        *self.call_count.write().unwrap() += 1;
        Ok(set.get_key(key_id))
    }
}

#[cfg(feature = "blocking")]
#[test]
pub fn decode_keys() {
    for kid in KIDS.iter() {
        TestKeyProvider::default().get_key(kid).unwrap();
    }
}

#[cfg(feature = "blocking")]
#[test]
pub fn test_client() {
    let client = Client::builder(AUDIENCE)
        .custom_key_provider(TestKeyProvider::default())
        .unsafe_mock_timestamp(AFTER_EXPIRATION)
        .build();
    assert_eq!(
        client.verify_token(TOKEN).map(|_| ()),
        Err(Error::InvalidToken(TokenValidationError::Claims(
            GoogleSigninClaimsError::Expired {
                now: AFTER_EXPIRATION,
                exp: 1526492533
            }
        )))
    );
}

#[cfg(feature = "blocking")]
#[test]
pub fn test_client_invalid_client_id() {
    let client = Client::builder("invalid client id")
        .custom_key_provider(TestKeyProvider::default())
        .build();
    let result = client.verify_token(TOKEN).map(|_| ());
    assert_eq!(
        result,
        Err(Error::InvalidToken(TokenValidationError::Claims(
            GoogleSigninClaimsError::InvalidAudience {
                expected: "invalid client id".into(),
                found: AUDIENCE.into()
            }
        )))
    )
}

#[cfg(feature = "blocking")]
#[test]
pub fn test_id_token() {
    let client = Client::builder(AUDIENCE)
        .custom_key_provider(TestKeyProvider::default())
        .unsafe_mock_timestamp(0) // pretend it's 1970
        .build();
    let id_token = client
        .verify_id_token(TOKEN)
        .expect("id token should be valid");
    assert_eq!(id_token.get_claims().get_audience(), AUDIENCE);
    assert_eq!(id_token.get_payload().get_domain(), None);
    assert_eq!(id_token.get_payload().get_email(), EMAIL);
}

#[cfg(feature = "async")]
#[tokio::test]
async fn decode_keys_async() {
    for kid in KIDS.iter() {
        TestKeyProvider::default().get_key_async(kid).await.unwrap();
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_client_async() {
    let client = Client::builder(AUDIENCE)
        .custom_key_provider(TestKeyProvider::default())
        .tokio()
        .unsafe_mock_timestamp(AFTER_EXPIRATION)
        .build();
    assert_eq!(
        client.verify_token(TOKEN).await.map(|_| ()),
        Err(Error::InvalidToken(TokenValidationError::Claims(
            GoogleSigninClaimsError::Expired {
                now: AFTER_EXPIRATION,
                exp: 1526492533
            }
        )))
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_client_invalid_client_id_async() {
    let client = Client::builder("invalid client id")
        .tokio()
        .custom_key_provider(TestKeyProvider::default())
        .build();
    let result = client.verify_token(TOKEN).await.map(|_| ());
    assert_eq!(
        result,
        Err(Error::InvalidToken(TokenValidationError::Claims(
            GoogleSigninClaimsError::InvalidAudience {
                expected: "invalid client id".into(),
                found: AUDIENCE.into()
            }
        )))
    )
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_id_token_async() {
    let client = Client::builder(AUDIENCE)
        .tokio()
        .custom_key_provider(TestKeyProvider::default())
        .unsafe_mock_timestamp(0) // pretend it's 1970
        .build();
    let id_token = client
        .verify_id_token(TOKEN)
        .await
        .expect("id token should be valid");
    assert_eq!(id_token.get_claims().get_audience(), AUDIENCE);
    assert_eq!(id_token.get_payload().get_domain(), None);
    assert_eq!(id_token.get_payload().get_email(), EMAIL);
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_deadlock_prevention() {
    let client = Client::builder(AUDIENCE)
        .tokio()
        .unsafe_mock_timestamp(0) // pretend it's 1970
        .build();
    join_all((0..10u8).map(|_| verify_token_async(&client))).await;
}

#[cfg(feature = "async")]
async fn verify_token_async(client: &GoogleSigninTokioClient) {
    let result = client.verify_id_token(TOKEN).await;
    assert_eq!(result, Err(Error::KeyDoesNotExist));
}
