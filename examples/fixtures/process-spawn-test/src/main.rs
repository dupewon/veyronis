use std::process::Command;

fn main() {
    #[cfg(windows)]
    let mut child = Command::new("cmd.exe")
        .args(["/C", "echo child process execution"])
        .spawn()
        .expect("spawn child");

    #[cfg(not(windows))]
    let mut child = Command::new("echo")
        .arg("child process execution")
        .spawn()
        .expect("spawn child");

    let status = child.wait().expect("wait child");
    println!("Process spawn test completed with status: {:?}", status);
}
