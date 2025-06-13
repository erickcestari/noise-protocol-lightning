pub mod noise;
pub mod client;

pub const PROTOCOL_NAME: &str = "Noise_XK_secp256k1_ChaChaPoly_SHA256";
pub const PROLOGUE: &str = "lightning";
pub const MESSAGE_VERSION: u8 = 0;
pub const MESSAGE_VERSION_SIZE: usize = 1;
pub const ACT_TWO_BUFFER_SIZE: usize = 50;
