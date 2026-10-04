// @category NDayNexus
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import java.io.FileWriter;
import java.io.Writer;

public class ExportFunctionEvidence extends GhidraScript {
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
        if (args.length < 2) throw new IllegalArgumentException("Usage: ExportFunctionEvidence.java <function> <output.json>");
        String wanted = args[0];
        Function found = null;
        for (Function candidate : currentProgram.getFunctionManager().getFunctions(true)) {
            if (candidate.getName().equals(wanted) || candidate.getName(true).equals(wanted)) {
                found = candidate;
                break;
            }
        }
        try (Writer writer = new FileWriter(args[1])) {
            writer.write("{\n  \"requested_function\": " + quote(wanted));
            if (found == null) {
                writer.write(",\n  \"found\": false\n}\n");
                println("Affected function not found: " + wanted);
                return;
            }

            int instructionCount = 0;
            InstructionIterator instructions = currentProgram.getListing().getInstructions(found.getBody(), true);
            while (instructions.hasNext()) { instructions.next(); instructionCount++; }
            String decompiled = "";
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                DecompileResults result = decompiler.decompileFunction(found, 90, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    decompiled = result.getDecompiledFunction().getC();
                }
            } finally {
                decompiler.dispose();
            }

            writer.write(",\n  \"found\": true");
            writer.write(",\n  \"entry\": " + quote(found.getEntryPoint().toString()));
            writer.write(",\n  \"frame_size\": " + found.getStackFrame().getFrameSize());
            writer.write(",\n  \"local_size\": " + found.getStackFrame().getLocalSize());
            writer.write(",\n  \"parameter_size\": " + found.getStackFrame().getParameterSize());
            writer.write(",\n  \"instruction_count\": " + instructionCount);
            writer.write(",\n  \"decompiled\": " + quote(decompiled) + "\n}\n");
            println("Exported Ghidra evidence for " + wanted + " at " + found.getEntryPoint());
        }
    }
}
