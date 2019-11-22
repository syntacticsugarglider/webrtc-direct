extern crate bindgen;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if !Path::new("../usrsctp/configure").exists() {
        let bin = fs::canonicalize("../usrsctp/bootstrap").unwrap();
        Command::new(bin)
            .current_dir("../usrsctp")
            .status()
            .expect("Failed to run bootstrap in ../usrsctp");
    }
    if !Path::new("../usrsctp/Makefile").exists() {
        let bin = fs::canonicalize("../usrsctp/configure").unwrap();
        Command::new(bin)
            .current_dir("../usrsctp")
            .status()
            .expect("Failed to run configure in ../usrsctp");
    }
    Command::new("make")
        .current_dir("../usrsctp")
        .status()
        .expect("Failed to run make in ../usrsctp");
    cc::Build::new().file("debug.c").compile("sctpdebug");
    let libdir = fs::canonicalize("../usrsctp/usrsctplib/.libs").unwrap();
    println!("cargo:rustc-link-lib=usrsctp");
    println!("cargo:rustc-link-lib=static=sctpdebug");
    println!(
        "cargo:rustc-link-search=native={}",
        libdir.to_str().unwrap()
    );
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
