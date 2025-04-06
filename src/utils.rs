use std::error::Error;

pub type GResult<T> = Result<T, Box<dyn Error>>;
