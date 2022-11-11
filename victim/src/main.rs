fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    log::info!("My Pid is {}", std::process::id());
    loop {
        std::thread::sleep(std::time::Duration::from_millis(3000));
        log::info!("Hello, world!");
    }
}
