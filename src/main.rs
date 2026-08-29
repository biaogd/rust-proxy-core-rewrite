fn main() {
    let topic = String::from("ownership and iterators");
    let values = [1, 2, 3, 4];
    let doubled: Vec<_> = values.iter().map(|value| value * 2).collect();

    println!("Learning Rust: {topic}");
    println!("Iterator result: {doubled:?}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn iterator_doubles_each_value() {
        let values = [1, 2, 3];
        let doubled: Vec<_> = values.iter().map(|value| value * 2).collect();
        assert_eq!(doubled, [2, 4, 6]);
    }
}
