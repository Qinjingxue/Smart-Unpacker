from pathlib import Path


def _toast_host_source() -> str:
    root = Path(__file__).resolve().parents[2]
    return (root / "native" / "toast_host" / "src" / "main.cpp").read_text(encoding="utf-8")


def test_toast_host_keeps_one_winrt_apartment_for_the_host_lifetime():
    source = _toast_host_source()
    run_host = source[source.index("int run_host(") : source.index("int self_test()")]
    release_presenter = run_host[
        run_host.index("const auto release_presenter") : run_host.index("const auto expire")
    ]

    assert run_host.count("WinrtApartmentScope apartment;") == 1
    assert "init_apartment" not in run_host
    assert "uninit_apartment" not in release_presenter


def test_toast_host_clears_cppwinrt_factories_before_apartment_shutdown():
    source = _toast_host_source()
    apartment_scope = source[
        source.index("class WinrtApartmentScope") : source.index("enum class MessageType")
    ]

    clear_at = apartment_scope.index("winrt::clear_factory_cache();")
    uninit_at = apartment_scope.index("winrt::uninit_apartment();")
    assert clear_at < uninit_at


def test_toast_host_signals_named_ready_event_after_pipe_creation():
    source = _toast_host_source()
    connect_pipe = source[
        source.index("HANDLE connect_server_pipe(") : source.index("int run_host(")
    ]

    assert 'argument_value(argc, argv, L"--ready-event")' in source
    assert "!ready_event" in source
    assert 'OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str())' in source
    assert connect_pipe.index("CreateNamedPipeW(") < connect_pipe.index("signal_ready_event(ready_event_name)")
    assert connect_pipe.index("signal_ready_event(ready_event_name)") < connect_pipe.index("ConnectNamedPipe(")
