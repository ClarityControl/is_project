// @category NDayNexus
import com.google.security.binexport.BinExport2Builder;
import com.google.security.binexport.IdaProMnemonicMapper;
import com.google.security.zynamics.BinExport.BinExport2;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Export target functions and their direct call neighborhood for large binaries. */
public class ExportScopedBinExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: ExportScopedBinExport.java <output.BinExport> <seed function>...");
        }

        Map<String, Function> named = new LinkedHashMap<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            named.putIfAbsent(function.getName(), function);
            named.putIfAbsent(function.getName(true), function);
        }

        Set<Function> selected = new HashSet<>();
        List<String> missing = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            Function function = named.get(args[i]);
            if (function == null) {
                missing.add(args[i]);
            } else {
                selected.add(function);
            }
        }
        if (selected.isEmpty()) {
            throw new IllegalStateException("No scoped BinExport seed functions were found: " + missing);
        }

        // Keep one call-graph hop on either side of each seed as context for BinDiff.
        Set<Function> neighborhood = new HashSet<>(selected);
        for (Function function : selected) {
            ReferenceIterator callers = currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint());
            while (callers.hasNext()) {
                Reference reference = callers.next();
                if (reference.getReferenceType().isCall()) {
                    Function caller = currentProgram.getFunctionManager()
                        .getFunctionContaining(reference.getFromAddress());
                    if (caller != null) neighborhood.add(caller);
                }
            }
            InstructionIterator instructions = currentProgram.getListing()
                .getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                for (Reference reference : currentProgram.getReferenceManager()
                        .getReferencesFrom(instruction.getAddress())) {
                    if (!reference.getReferenceType().isCall()) continue;
                    Function callee = currentProgram.getFunctionManager()
                        .getFunctionContaining(reference.getToAddress());
                    if (callee != null) neighborhood.add(callee);
                }
            }
        }

        AddressSet scope = new AddressSet();
        List<String> names = new ArrayList<>();
        for (Function function : neighborhood) {
            scope.add(function.getBody());
            names.add(function.getName() + "@" + function.getEntryPoint());
        }
        println("Scoped BinExport contains " + neighborhood.size() + " functions; missing seeds: " + missing);

        BinExport2Builder builder = new BinExport2Builder(currentProgram, scope);
        builder.setMnemonicMapper(new IdaProMnemonicMapper(currentProgram.getLanguage()));
        builder.setAddressOffset(currentProgram.getImageBase().getOffset());
        builder.setPrependNamespace(true);
        BinExport2 export = builder.build();
        try (FileOutputStream output = new FileOutputStream(args[0])) {
            export.writeTo(output);
        }
        try (FileWriter scopeFile = new FileWriter(args[0] + ".scope.txt")) {
            for (String name : names) scopeFile.write(name + "\n");
        }
        println("Scoped BinExport written to " + args[0]);
    }
}
