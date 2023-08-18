from typing import Iterable

from cpkfile import CpkFile, CpkInfo


class UnionCpk(CpkFile):
    def __init__(self, cpks: Iterable[CpkFile]):
        self.cpks = list(cpks)

    def get_cpks(self):
        return self.cpks

    def dump_patch_info(self):
        """
        Print out a short version of all the changes done by each patch
        """
        # Make a shallow copy of the "root" CPK, and skip iteration of it
        merged_infos = dict(self.cpks[0].infos_by_path)

        for cpk in self.cpks[1:]:
            print(f"building diff for CPK: {cpk.name}")
            for key, patch_info in cpk.infos_by_path.items():
                if key not in merged_infos:
                    print(f"new file, this is VERY UNUSUAL: {key}")
                    continue

                if patch_info == merged_infos[key]:
                    print(f"patch file with identical content: {key}")
                    continue

                if patch_info.get('FileSize') != merged_infos[key].get('FileSize'):
                    print(f"updated patch file with different info: {key}")
                    print(set(patch_info.toc_data.items()) ^ set(merged_infos[key].toc_data.items()))

            print()
            merged_infos.update(cpk.infos_by_path)

    def infolist(self) -> Iterable[CpkInfo]:
        merged_infos = dict()
        for cpk in self.cpks:
            merged_infos.update(cpk.infos_by_path)

        return merged_infos.values()
