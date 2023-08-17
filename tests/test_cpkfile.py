from cpkfile import CpkFile


def test_constructor():
    cpk = CpkFile("fake name dot.cpk", [])


def test_header_parse():
    cpk = CpkFile.fromLocalPath("./generated-cpk-toc.cpk")
