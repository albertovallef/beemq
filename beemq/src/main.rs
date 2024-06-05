use beemq_codec::add;

fn main() {
    let num_one = 10;
    let num_two = 5;
    let result = beemq_codec::add(num_one, num_two);
    println!("Hello, world! {num_one} plus {num_two} is {}!", result);
}
