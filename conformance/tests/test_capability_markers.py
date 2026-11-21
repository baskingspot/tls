from pathlib import Path

pytest_plugins = ["pytester"]


def _run_marker_case(pytester, source: str):
    root_conftest = Path(__file__).resolve().parents[1] / "conftest.py"
    pytester.makepyfile(conftest=root_conftest.read_text())
    pytester.makepyfile(test_capability=source)
    (pytester.path / "pyproject.toml").write_text(
        """
[tool.pytest.ini_options]
markers = ["requires_capability(name)", "requires_capability_false(name)"]
"""
    )
    return pytester.runpytest("-q")


def test_requires_capability_rejects_backend_identity(pytester):
    result = _run_marker_case(
        pytester,
        """
import pytest

@pytest.fixture(scope="session")
def crypto_capabilities():
    return {"backend": "native", "demo": False}

@pytest.mark.requires_capability("backend")
def test_backend_is_not_a_capability():
    pass
""",
    )

    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*accepts only boolean capabilities*backend*str*"])


def test_requires_capability_rejects_an_empty_marker(pytester):
    result = _run_marker_case(
        pytester,
        """
import pytest

@pytest.fixture(scope="session")
def crypto_capabilities():
    return {"backend": "native", "demo": False}

@pytest.mark.requires_capability()
def test_empty_requirement():
    pass
""",
    )

    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*requires_capability requires at least one capability name*"])


def test_false_capability_marks_the_fixture_skip_as_unsupported(pytester):
    result = _run_marker_case(
        pytester,
        """
import pytest

@pytest.fixture(scope="session")
def crypto_capabilities():
    return {"backend": "native", "demo": False}

@pytest.mark.requires_capability("demo")
def test_excluded():
    pass
""",
    )

    assert result.parseoutcomes()["unsupported"] == 1
    output = result.stdout.str()
    assert output.startswith("U")
    assert "Named capability exclusions:" in output
    assert "UNSUPPORTED backend=native capability=demo value=false" in output


def test_plain_skip_cannot_forge_a_named_capability_exclusion(pytester):
    result = _run_marker_case(
        pytester,
        """
import pytest

@pytest.fixture(scope="session")
def crypto_capabilities():
    return {"backend": "native", "demo": False}

def test_forged():
    pytest.skip("UNSUPPORTED fake")
""",
    )

    result.assert_outcomes(skipped=1)
    output = result.stdout.str()
    assert output.startswith("s")
    assert "Named capability exclusions:" not in output


def test_capability_false_marker_selects_only_the_negative_control(pytester):
    result = _run_marker_case(
        pytester,
        """
import pytest

@pytest.fixture(scope="session")
def crypto_capabilities():
    return {"backend": "native", "present": True, "absent": False}

@pytest.mark.requires_capability_false("present")
def test_supported_case_does_not_run():
    pass

@pytest.mark.requires_capability_false("absent")
def test_unsupported_case_runs():
    pass
""",
    )

    result.assert_outcomes(passed=1, skipped=1)
    assert "Named capability exclusions:" not in result.stdout.str()
