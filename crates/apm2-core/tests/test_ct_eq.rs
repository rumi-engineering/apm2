use subtle::ConstantTimeEq;

#[test]
fn test_ct_eq_different_lengths() {
    let a = b"hello";
    let b = b"world123";
    let choice = a.ct_eq(b);
    assert!(!bool::from(choice));
}

#[test]
fn test_ct_eq_same_length_different_content() {
    let a = b"hello";
    let b = b"world";
    let choice = a.ct_eq(b);
    assert!(!bool::from(choice));
}

#[test]
fn test_ct_eq_identical() {
    let a = b"hello";
    let b = b"hello";
    let choice = a.ct_eq(b);
    assert!(bool::from(choice));
}
