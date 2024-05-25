use beemq_codec;

fn main() {
    let num_one = 10;
    let num_two = 5;
    println!(
        "Hello, world! {num_one} plus {num_two} is {}!",
        beemq_codec::add(num_one, num_two)
    );
}
