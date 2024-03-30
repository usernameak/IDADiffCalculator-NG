#define USE_STANDARD_FILE_FUNCTIONS
#include <loader.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <strlist.hpp>
#include <hexrays.hpp>
#include <unordered_set>

class IDADiffCalculator final : public plugmod_t {
    char m_folderPath[QMAXPATH] = {};

    enum ExportOptions : ushort {
        EXPORT_BASE_ADDR           = 1 << 0,
        EXPORT_SEGMENTS            = 1 << 1,
        EXPORT_XREFS               = 1 << 2,
        EXPORT_ASM                 = 1 << 3,
        EXPORT_FUNCS               = 1 << 4,
        EXPORT_GLOBALS             = 1 << 5,
        EXPORT_NAMES               = 1 << 6,
        EXPORT_RTTI                = 1 << 7,
        EXPORT_VTABLES             = 1 << 8,
        EXPORT_STRINGS             = 1 << 9,
        EXPORT_IMAGE_RELATIVE_RTTI = 1 << 10
    };

    ushort m_exportOptions =
        EXPORT_BASE_ADDR |
        EXPORT_SEGMENTS |
        EXPORT_XREFS |
        EXPORT_ASM |
        EXPORT_FUNCS |
        EXPORT_GLOBALS |
        EXPORT_NAMES |
        EXPORT_RTTI |
        EXPORT_VTABLES |
        EXPORT_STRINGS |
        EXPORT_IMAGE_RELATIVE_RTTI;

    bool m_warnDontSave = false;

    int m_pointerSize = 0;

    std::unordered_set<ea_t> m_rttiDone;

public:
    ~IDADiffCalculator() override = default;

    bool run(size_t arg) override {
        msg("Beginning export\n");

        m_pointerSize = getPointerSize();
        if (m_pointerSize == 0) {
            warning("Cannot determine pointer size");
            return false;
        }

        m_rttiDone.clear();

        m_warnDontSave = false;
        int result     = ask_form(
            "IDADiffCalculator export options\n"
                "\n"
                "<##Export options##Export base address:C>\n"
                "<##Export segments:C>\n"
                "<##Export xrefs:C>\n"
                "<##Export asm:C>\n"
                "<##Export funcs:C>\n"
                "<##Export globals:C>\n"
                "<##Export names:C>\n"
                "<##Export RTTI:C>\n"
                "<##Export vtables:C>\n"
                "<##Export strings:C>\n"
                "<##Image-relative RTTI descriptors:C>>\n"
                "\n"
                "<Export to folder:F:512:40>\n",
            &m_exportOptions,
            &m_folderPath);
        if (result <= 0) return false;

        if (m_exportOptions & EXPORT_BASE_ADDR) {
            show_wait_box("NODELAY\nExporting base address...");
            FILE *handle = prepareFile("base");
            fprintf(handle, "baseaddress\t%llX\n", (unsigned long long)get_imagebase());
            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & EXPORT_SEGMENTS) {
            show_wait_box("NODELAY\nExporting segments...");
            FILE *handle = prepareFile("segment");
            for (segment_t *seg = get_first_seg(); seg; seg = get_next_seg(seg->start_ea)) {
                qstring segName;
                get_segm_name(&segName, seg, 0);
                fprintf(handle, "segment\t%llX\t%llX\t%s\t%X\n",
                    (unsigned long long)seg->start_ea,
                    (unsigned long long)seg->end_ea,
                    segName.c_str(),
                    seg->perm);
            }
            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & EXPORT_STRINGS) {
            show_wait_box("NODELAY\nExporting strings...");
            FILE *handle = prepareFile("string");

            get_strlist_options(); // nani?
            build_strlist();
            size_t numStrings = get_strlist_qty();
            for (size_t i = 0; i < numStrings; i++) {
                string_info_t strInfo;
                if (!get_strlist_item(&strInfo, i)) continue;

                qstring str;
                get_strlit_contents(&str, strInfo.ea, strInfo.length, strInfo.type);
                str.replace("\r", "$BR$");
                str.replace("\n", "$NL$");
                str.replace("\t", "$TB$");

                fprintf(handle, "string\t%llX\t%X\t%X\t%s\n",
                    (unsigned long long)strInfo.ea,
                    strInfo.length,
                    strInfo.type,
                    str.c_str());
            }

            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & EXPORT_XREFS) {
            show_wait_box("NODELAY\nExporting xrefs...");
            FILE *handle = prepareFile("xrefs");
            for (segment_t *seg = get_first_seg(); seg; seg = get_next_seg(seg->start_ea)) {
                for (ea_t ea = seg->start_ea; ea < seg->end_ea; ea++) {
                    xrefblk_t xb{};
                    for (bool ok = xb.first_to(ea, 0); ok; ok = xb.next_to()) {
                        if (xb.type == fl_F) continue;

                        fprintf(handle, "xref\t%llX\t%llX\t%X\n",
                            (unsigned long long)ea,
                            (unsigned long long)xb.from,
                            xb.type);
                    }
                }
            }

            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & EXPORT_ASM) {
            show_wait_box("NODELAY\nExporting asm...");
            FILE *handle = prepareFile("asm");
            for (segment_t *seg = get_first_seg(); seg; seg = get_next_seg(seg->start_ea)) {
                if (!(seg->perm & SEGPERM_EXEC)) continue;
                ea_t ea = seg->start_ea;
                if (!is_head(ea)) {
                    ea = next_head(ea, seg->end_ea);
                }
                for (; ea < seg->end_ea && ea != BADADDR; ea = next_head(ea, seg->end_ea)) {
                    m_warnDontSave = true;
                    op_hex(ea, -1);

                    qstring disasm_line;
                    if (!generate_disasm_line(&disasm_line, ea, 0)) continue;
                    tag_remove(&disasm_line);

                    qstring insn_mnem;
                    print_insn_mnem(&insn_mnem, ea);

                    fprintf(handle, "asm\t%llX\t%s\t%s",
                        (unsigned long long)ea,
                        disasm_line.c_str(),
                        insn_mnem.c_str());

                    insn_t ins;
                    if (decode_insn(&ins, ea) > 0) {
                        for (op_t &op : ins.ops) {
                            if (op.type == o_void) continue;

                            fprintf(handle, "\t%X %X ",
                                op.n,
                                op.type);

                            if (op.dtype != dt_byte) { // wtf, 0 is byte
                                fprintf(handle, "%X", op.dtype);
                            }
                            fprintf(handle, " ");

                            if (op.reg != 0) {
                                fprintf(handle, "%X", op.reg);
                            }
                            fprintf(handle, " ");

                            if (op.phrase != 0) {
                                fprintf(handle, "%X", op.phrase);
                            }
                            fprintf(handle, " ");

                            if (op.value != 0) {
                                fprintf(handle, "%llX", op.value);
                            }
                            fprintf(handle, " ");

                            if (op.addr != 0) {
                                fprintf(handle, "%llX", op.addr);
                            }
                            fprintf(handle, " ");

                            if (op.flags != OF_SHOW) {
                                fprintf(handle, "%X", op.flags);
                            }
                            fprintf(handle, " ");

                            if (op.specflag1 != 0) {
                                fprintf(handle, "%X", op.specflag1);
                            }
                            fprintf(handle, " ");

                            if (op.specflag2 != 0) {
                                fprintf(handle, "%X", op.specflag2);
                            }
                            fprintf(handle, " ");

                            if (op.specflag3 != 0) {
                                fprintf(handle, "%X", op.specflag3);
                            }
                            fprintf(handle, " ");

                            if (op.specflag4 != 0) {
                                fprintf(handle, "%X", op.specflag4);
                            }
                            fprintf(handle, " ");

                            if (op.specval != 0) {
                                fprintf(handle, "%llX", op.specval);
                            }
                        }
                    }
                    fprintf(handle, "\n");
                }
            }
            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & EXPORT_FUNCS) {
            show_wait_box("NODELAY\nExporting funcs...");
            FILE *handle = prepareFile("func");

            // basically a copy of idautils.Functions
            func_t *func;
            ea_t end = inf_get_max_ea();
            {
                ea_t start    = inf_get_min_ea();
                func_t *chunk = get_fchunk(start);
                if (!chunk) chunk = get_next_fchunk(start);
                while (chunk && chunk->start_ea < end && (chunk->flags & FUNC_TAIL) != 0) {
                    chunk = get_next_fchunk(chunk->start_ea);
                }
                func = chunk;
            }

            for (; func && func->start_ea < end; func = get_next_func(func->start_ea)) {
                m_warnDontSave = true;

                fprintf(handle, "func\t%llX\t%llX",
                    (unsigned long long)func->start_ea,
                    (unsigned long long)func->end_ea);

                fprintf(handle, "\n");
            }

            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & EXPORT_GLOBALS) {
            show_wait_box("NODELAY\nExporting globals...");
            FILE *handle = prepareFile("global");

            for (segment_t *seg = get_first_seg(); seg; seg = get_next_seg(seg->start_ea)) {
                if (seg->perm & SEGPERM_EXEC) {
                    qstring segname;
                    get_segm_name(&segname, seg);
                    if (segname == ".text") continue;
                }

                for (ea_t ea = seg->start_ea; ea < seg->end_ea; ea++) {
                    if (get_func(ea)) continue;

                    xrefblk_t xb{};
                    bool hasXrefs = false;
                    for (bool ok = xb.first_to(ea, 0); ok; ok = xb.next_to()) {
                        if (xb.type == fl_F) continue;
                        hasXrefs = true;
                        break;
                    }
                    if (!hasXrefs) continue;

                    fprintf(handle, "global\t%llX\t", ea);
                    tinfo_t rti;
                    bool rtiValid = true;
                    if (!get_tinfo(&rti, ea)) {
                        if (!guess_tinfo(&rti, ea)) {
                            rtiValid = false;
                        }
                    }
                    if (rtiValid) {
                        qstring gti;
                        const char *gtic;
                        if (rti.print(&gti)) {
                            gtic = gti.c_str();
                        } else {
                            gtic = rti.dstr();
                        }
                        if (gtic) {
                            fprintf(handle, "%s", gtic);
                        }
                    }
                    fprintf(handle, "\n");
                }
            }

            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & EXPORT_NAMES) {
            show_wait_box("NODELAY\nExporting names...");
            FILE *handle = prepareFile("name");

            size_t numNames = get_nlist_size();
            for (size_t i = 0; i < numNames; i++) {
                const char *name = get_nlist_name(i);

                fprintf(handle, "name\t%llX\t%s\t",
                    (unsigned long long)get_nlist_ea(i),
                    name);

                qstring nameStr;
                if (demangle_name(&nameStr, name, getinf(INF_SHORT_DEMNAMES)) > 0) {
                    fprintf(handle, "%s", nameStr.c_str());
                }
                fprintf(handle, "\n");
            }

            finishFile(handle);
            hide_wait_box();
        }

        if (user_cancelled()) return false;

        if (m_exportOptions & (EXPORT_RTTI | EXPORT_VTABLES)) {
            show_wait_box("NODELAY\nExporting vtables...");

            FILE *rtHandle = nullptr, *vtHandle = nullptr;
            if (m_exportOptions & EXPORT_RTTI) {
                rtHandle = prepareFile("rtti");
            }
            if (m_exportOptions & EXPORT_VTABLES) {
                vtHandle = prepareFile("vtable");
            }

            for (segment_t *seg = get_first_seg(); seg; seg = get_next_seg(seg->start_ea)) {
                qstring segname;
                get_segm_name(&segname, seg);
                if (segname != ".rdata") continue;

                for (ea_t ea = seg->start_ea; ea < seg->end_ea; ea += m_pointerSize) {
                    writeRTTI(vtHandle, rtHandle, ea);
                }
            }

            if (rtHandle) finishFile(rtHandle);
            if (vtHandle) finishFile(vtHandle);

            hide_wait_box();
        }

        if (user_cancelled()) return false;

        msg("Done with export\n");
        if (m_warnDontSave) {
            warning("Close WITHOUT SAVING now!\n");
        }

        return true;
    }

    static plugmod_t *init() {
        return new IDADiffCalculator;
    }

private:
    static bool isCode(ea_t ea) {
        if (ea == 0 || ea == BADADDR) return false;
        segment_t *seg = getseg(ea);
        if (!seg) return false;
        if (!(seg->perm & SEGPERM_EXEC)) return false;
        return true;
    }

    bool canWriteRTTI(ea_t ea) {
        return m_rttiDone.insert(ea).second;
    }

    void writeVTable(FILE *vtHandle, ea_t ea) {
        {
            ea_t eaFn;
            if (m_pointerSize == 8) {
                eaFn = get_qword(ea);
            } else {
                eaFn = get_dword(ea);
            }
            if (!isCode(eaFn)) return;

            bool hasXref = false;
            xrefblk_t xb{};
            for (bool ok = xb.first_to(ea, 0); ok; ok = xb.next_to()) {
                if (xb.type == fl_F) continue;
                if (!isCode(xb.from)) continue;
                hasXref = true;
                break;
            }
            if (!hasXref) return;
        }

        fprintf(vtHandle, "vtable\t%llX", ea);

        ea_t eaLoc = ea - m_pointerSize;
        ea_t locPtr;
        if (m_pointerSize == 8) {
            locPtr = get_qword(eaLoc);
        } else {
            locPtr = get_dword(eaLoc);
        }
        fprintf(vtHandle, "\t%llX", locPtr);

        bool isFirst = true;
        while (true) {
            ea_t eaFn;
            if (m_pointerSize == 8) {
                eaFn = get_qword(ea);
            } else {
                eaFn = get_dword(ea);
            }
            if (!isCode(eaFn)) break;
            if (!isFirst) {
                bool hasXref = false;
                xrefblk_t xb{};
                for (bool ok = xb.first_to(ea, 0); ok; ok = xb.next_to()) {
                    if (xb.type == fl_F) continue;
                    if (!isCode(xb.from)) continue;
                    hasXref = true;
                    break;
                }
                if (hasXref) break;
            }
            fprintf(vtHandle, "\t%llX", eaFn);
            ea += m_pointerSize;
            isFirst = false;
        }
        fprintf(vtHandle, "\n");
    }

    void writeRTTITdesc(FILE *handle, ea_t ea) {
        if (!canWriteRTTI(ea)) return;

        fprintf(handle, "rtti_tdesc\t%llX", ea);
        uint64 tptr;
        if (m_pointerSize == 8) {
            tptr = get_qword(ea);
            ea += 8;
        } else {
            tptr = get_dword(ea);
            ea += 4;
        }
        fprintf(handle, "\t%llX", tptr);
        fprintf(handle, "\t%X", get_dword(ea)); // data of some sort
        ea += m_pointerSize;                    // this is correct we skip ptr size even if data is 4
        fprintf(handle, "\t");                  // data of some sort
        qstring name;
        while (true) {
            uchar b = get_byte(ea);
            if (b == 0) break;
            name += static_cast<char>(b);
            ea++;
        }
        fprintf(handle, "%s\t", name.c_str());
        if (name.starts_with(".?A")) {
            name = qstring("??_R0") + name.substr(1);
            qstring name2;

            if (demangle_name(&name2, name.c_str(), getinf(INF_SHORT_DEMNAMES)) > 0) {
                size_t idx = name2.find(" `RTTI Type Descriptor'");
                if (idx != qstring::npos) {
                    name2 = name2.substr(0, idx);
                }
                fprintf(handle, "%s", name2.c_str());
            }
        }
        fprintf(handle, "\n");
    }

    void writeRTTIBC(FILE *handle, ea_t ea) {
        if (!canWriteRTTI(ea)) return;

        fprintf(handle, "rtti_bc\t%llX", ea);

        uint32 tdesc = get_dword(ea); // tdesc
        ea += 4;
        fprintf(handle, "\t%X", tdesc);

        uint32 numContainedBases = get_dword(ea); // numContainedBases
        ea += 4;
        fprintf(handle, "\t%X", numContainedBases);

        uint32 pmd0 = get_dword(ea); // pmd0
        ea += 4;
        fprintf(handle, "\t%X", pmd0);

        uint32 pmd1 = get_dword(ea); // pmd1
        ea += 4;
        fprintf(handle, "\t%X", pmd1);

        uint32 pmd2 = get_dword(ea); // pmd2
        ea += 4;
        fprintf(handle, "\t%X", pmd2);

        uint32 attributes = get_dword(ea); // attributes
        ea += 4;
        fprintf(handle, "\t%X", attributes);

        fprintf(handle, "\n");

        if (tdesc != 0) {
            writeRTTITdesc(handle, tdesc + (m_exportOptions & EXPORT_IMAGE_RELATIVE_RTTI ? get_imagebase() : 0));
        }
    }

    void writeRTTIBCA(FILE *handle, ea_t ea, size_t count) {
        if (!canWriteRTTI(ea)) return;

        fprintf(handle, "rtti_bca\t%llX", ea);

        ea_t origEa = ea;
        for (size_t i = 0; i < count; i++) {
            uint32 bref = get_dword(ea);
            ea += 4;
            fprintf(handle, "\t%X", bref);
        }

        fprintf(handle, "\n");

        ea = origEa;
        for (size_t i = 0; i < count; i++) {
            uint32 bref = get_dword(ea);
            ea += 4;
            if (bref != 0) {
                writeRTTIBC(handle, bref + (m_exportOptions & EXPORT_IMAGE_RELATIVE_RTTI ? get_imagebase() : 0));
            }
        }
    }

    void writeRTTICdesc(FILE *handle, ea_t ea) {
        if (!canWriteRTTI(ea)) return;

        fprintf(handle, "rtti_cdesc\t%llX", ea);

        uint32 signature = get_dword(ea); // signature
        ea += 4;
        fprintf(handle, "\t%X", signature);

        uint32 attributes = get_dword(ea); // attributes
        ea += 4;
        fprintf(handle, "\t%X", attributes);

        uint32 numb = get_dword(ea); // numb
        ea += 4;
        fprintf(handle, "\t%X", numb);

        uint32 bca = get_dword(ea); // bca
        ea += 4;
        fprintf(handle, "\t%X", bca);

        fprintf(handle, "\n");

        if (bca != 0) {
            writeRTTIBCA(handle, bca + (m_exportOptions & EXPORT_IMAGE_RELATIVE_RTTI ? get_imagebase() : 0), numb);
        }
    }

    void writeRTTIComplete(FILE *handle, ea_t ea) {
        if (!canWriteRTTI(ea)) return;

        fprintf(handle, "rtti_complete\t%llX", ea);

        uint32 signature = get_dword(ea); // signature
        ea += 4;
        fprintf(handle, "\t%X", signature);

        uint32 offset = get_dword(ea); // offset
        ea += 4;
        fprintf(handle, "\t%X", offset);

        uint32 cdoffset = get_dword(ea); // cdoffset
        ea += 4;
        fprintf(handle, "\t%X", cdoffset);

        uint32 tdesc = get_dword(ea); // tdesc
        ea += 4;
        fprintf(handle, "\t%X", tdesc);

        uint32 cdesc = get_dword(ea); // cdesc
        ea += 4;
        fprintf(handle, "\t%X", cdesc);

        uint32_t obase = 0;
        if (m_pointerSize == 8) {
            obase = get_dword(ea);
        }
        fprintf(handle, "\t%X\n", obase);

        if (tdesc != 0) {
            writeRTTITdesc(handle, tdesc + (m_exportOptions & EXPORT_IMAGE_RELATIVE_RTTI ? get_imagebase() : 0));
        }

        if (cdesc != 0) {
            writeRTTICdesc(handle, cdesc + (m_exportOptions & EXPORT_IMAGE_RELATIVE_RTTI ? get_imagebase() : 0));
        }
    }

    void writeRTTI(FILE *vtHandle, FILE *rtHandle, ea_t ea) {
        if (m_exportOptions & EXPORT_VTABLES) {
            writeVTable(vtHandle, ea);
        }
        if (!(m_exportOptions & EXPORT_RTTI)) return;
        qstring nameAddr, demNameAddr;
        if (get_name(&nameAddr, ea, GN_VISIBLE | calc_gtn_flags(BADADDR, ea)) <= 0) {
            return;
        }
        if (demangle_name(&demNameAddr, nameAddr.c_str(), getinf(INF_SHORT_DEMNAMES)) <= 0) {
            return;
        }
        nameAddr = demNameAddr;
        if (nameAddr.find("`vftable'") == qstring::npos) return;
        ea -= m_pointerSize;
        if (m_pointerSize == 8) {
            ea = get_qword(ea);
        } else {
            ea = get_dword(ea);
        }
        segment_t *seg = getseg(ea);
        qstring segName;
        if (!seg || get_segm_name(&segName, seg) <= 0) return;
        if (segName != ".rdata") return;

        writeRTTIComplete(rtHandle, ea);
    }

    static int getPointerSize() {
        if (inf_is_64bit()) {
            return 8;
        }
        if (inf_is_32bit_exactly()) {
            return 4;
        }
        return 0;
    }

    FILE *prepareFile(const char *filename) const {
        char outFilename[QMAXPATH];
        sprintf_s(outFilename, "%s/idaexport_%s.txt", m_folderPath, filename);

        FILE *fh = fopen(outFilename, "w");
        fprintf(fh, "version\t%X\n", 1);

        return fh;
    }

    void finishFile(FILE *fp) const {
        fclose(fp);
    }
};

plugin_t PLUGIN = {
    .version       = IDP_INTERFACE_VERSION,
    .flags         = PLUGIN_MULTI | PLUGIN_UNL,
    .init          = &IDADiffCalculator::init,
    .term          = nullptr,
    .run           = nullptr,
    .comment       = "",
    .help          = "",
    .wanted_name   = "IDADiffCalculator-NG",
    .wanted_hotkey = ""
};
