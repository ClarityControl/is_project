// @category NDayNexus
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import java.io.FileWriter;
import java.io.Writer;

public class ExportCandidateEvidence extends GhidraScript {
    private String quote(String value) {
        if (value == null) return "null";
        StringBuilder escaped = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '"') escaped.append('\\').append(c);
            else if (c == '\n') escaped.append("\\n");
            else if (c == '\r') escaped.append("\\r");
            else if (c == '\t') escaped.append("\\t");
            else if (c < 0x20) escaped.append(String.format("\\u%04x", (int)c));
            else escaped.append(c);
        }
        return escaped.append('"').toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("Usage: ExportCandidateEvidence.java <output.json> <address>...");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (Writer writer = new FileWriter(args[0])) {
            writer.write("{\n  \"functions\": [\n");
            boolean first = true;
            for (int i = 1; i < args.length; i++) {
                String raw = args[i].replaceFirst("^0[xX]", "");
                long offset = Long.parseUnsignedLong(raw, 16);
                Address address = currentProgram.getImageBase().add(offset);
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                if (function == null) function = currentProgram.getFunctionManager().getFunctionContaining(address);
                if (function == null) continue;

                String decompiled = "";
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    decompiled = result.getDecompiledFunction().getC();
                }
                int instructionCount = 0;
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext()) { instructions.next(); instructionCount++; }
                if (!first) writer.write(",\n");
                first = false;
                writer.write("    {\"name\": " + quote(function.getName())
                    + ", \"entry\": " + quote(function.getEntryPoint().toString())
                    + ", \"frame_size\": " + function.getStackFrame().getFrameSize()
                    + ", \"instruction_count\": " + instructionCount
                    + ", \"decompiled\": " + quote(decompiled) + "}");
            }
            writer.write("\n  ]\n}\n");
        } finally {
            decompiler.dispose();
        }
    }
}
