use std::sync::Mutex;

fn main() {
    let m = Mutex::new(0u32);
    let first = m.lock().unwrap();
    let second = m.lock().unwrap(); // double lock on the same mutex -> deadlock
    println!("{} {}", *first, *second);
}
