use vstd::prelude::*;

use doubly_linked_xor::DListXor;

verus! {

#[verifier::external_body]
fn print_result(msg: &'static str, value: u32) {
    println!("{}: {value}", msg);
}

fn main() {
    let mut t = DListXor::<u32>::new();
    t.push_back(2);
    t.push_back(3);
    t.push_front(1);  // 1, 2, 3
    print_result("pushed", 2);
    print_result("pushed", 3);
    print_result("pushed", 1);
    let x = t.pop_back();  // 3
    let y = t.pop_front();  // 1
    let z = t.pop_front();  // 2
    assert(x == 3);
    assert(y == 1);
    assert(z == 2);
    print_result("popped", x);
    print_result("popped", y);
    print_result("popped", z);
}

} // verus!
