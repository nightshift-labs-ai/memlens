// Headless Ghidra check of a MemLens kernel.elf and its C header.
// args: <header.h> <sizes.tsv> <symbol> [<symbol> ...]
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class MemLensCheck extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        println("RESULT format " + currentProgram.getExecutableFormat() + " lang " + currentProgram.getLanguageID()
            + " image base " + currentProgram.getImageBase());
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        long init = 0;
        for (MemoryBlock b : blocks) if (b.isInitialized()) init += b.getSize();
        println("RESULT blocks " + blocks.length + " initialized bytes " + init);
        println("RESULT symbols " + currentProgram.getSymbolTable().getNumSymbols());
        for (int i = 2; i < a.length; i++) {
            SymbolIterator it = currentProgram.getSymbolTable().getSymbols(a[i]);
            if (!it.hasNext()) { println("RESULT MISSING " + a[i]); continue; }
            Symbol s = it.next();
            Address ea = s.getAddress();
            StringBuilder sb = new StringBuilder();
            if (a[i].equals("linux_banner")) {
                byte[] bytes = new byte[80];
                currentProgram.getMemory().getBytes(ea, bytes);
                sb.append(new String(bytes, "ISO-8859-1").split("\0")[0].trim());
            } else {
                disassemble(ea);
                Instruction ins = getInstructionAt(ea);
                for (int n = 0; n < 6 && ins != null; n++, ins = ins.getNext()) sb.append(ins).append(" ; ");
            }
            println("RESULT " + a[i] + " @ " + ea + " : " + sb);
        }
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CParser parser = new CParser(dtm, true, null);
        long t = System.currentTimeMillis();
        try (InputStream in = new BufferedInputStream(new FileInputStream(a[0]))) {
            parser.parse(in);
            println("RESULT parser ok in " + (System.currentTimeMillis() - t) + " ms");
        } catch (Throwable e) {
            println("RESULT PARSER FAILED after " + (System.currentTimeMillis() - t) + " ms: " + e.toString());
        }
        Map<String, Integer> found = new HashMap<>();
        Iterator<DataType> all = dtm.getAllDataTypes();
        while (all.hasNext()) { DataType d = all.next(); found.putIfAbsent(d.getName(), d.getLength()); }
        int checked = 0, missing = 0, wrong = 0;
        List<String> examples = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get(a[1]))) {
            String[] c = line.split("\t");
            if (c.length < 2) continue;
            checked++;
            Integer got = found.get(c[0]);
            if (got == null) { missing++; if (examples.size() < 15) examples.add("missing " + c[0]); }
            else if (got != Integer.parseInt(c[1])) { wrong++; if (examples.size() < 15) examples.add("size " + c[0] + " ghidra " + got + " isf " + c[1]); }
        }
        println("RESULT types checked " + checked + " missing " + missing + " wrong size " + wrong);
        for (String e : examples) println("RESULT   " + e);
    }
}
