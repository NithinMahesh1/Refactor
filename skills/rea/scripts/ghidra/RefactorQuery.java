import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Answers one query about the program that Ghidra has open: its functions, its defined strings,
 * or the decompiled text of one function. The query comes from a JSON file and the answer goes
 * to a JSON result file.
 * ghidra-query.mjs runs it with: analyzeHeadless ... -postScript RefactorQuery.java <query file>.
 * It only reads the program: it starts no transaction and changes nothing.
 */
public class RefactorQuery extends GhidraScript {

    /** Longest string text in a strings item; a longer text is cut and flagged. */
    private static final int MAX_STRING_CHARS = 200;

    /** Longest function name in a result; a longer name is cut and flagged. */
    private static final int MAX_NAME_CHARS = 500;

    /** Longest text of the filter, name and address fields of the query. */
    private static final int MAX_QUERY_TEXT_CHARS = 500;

    /** Largest size of the query file, in bytes. */
    private static final long MAX_QUERY_FILE_BYTES = 65536;

    /** Time limit for one decompile, in seconds. */
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    /** Default for the max_chars field of the query. */
    private static final int DEFAULT_MAX_CHARS = 20000;

    /** Largest max_chars that a query may ask for. */
    private static final int MAX_MAX_CHARS = 200000;

    /** Default for the limit field of the query. */
    private static final int DEFAULT_LIMIT = 100;

    /** Largest limit that a query may ask for. */
    private static final int MAX_LIMIT = 1000;

    /** Largest cursor that a query may ask for. */
    private static final long MAX_CURSOR = 1000000000L;

    /** Largest number of candidates in a decompile result. */
    private static final int MAX_CANDIDATES = 50;

    /**
     * Error inside a query that becomes an error result with a code.
     */
    private static final class QueryError extends Exception {
        private final String code;

        /**
         * Makes a query error.
         * @param code machine-readable code
         * @param message plain text, never a path
         */
        QueryError(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    /**
     * Reads the query file, runs the query and writes the result file. The result file must be
     * a new file in the folder of the query file; otherwise the script writes nothing.
     * @throws Exception when the query file cannot be read
     */
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("RefactorQuery: expected one argument, the query file");
            return;
        }

        Path queryPath = Path.of(args[0]).toAbsolutePath().normalize();
        if (Files.size(queryPath) > MAX_QUERY_FILE_BYTES) {
            println("RefactorQuery: the query file is too large");
            return;
        }
        String text = Files.readString(queryPath, StandardCharsets.UTF_8);
        JsonObject q = new Gson().fromJson(text, JsonObject.class);
        JsonElement outField = q == null ? null : q.get("out");
        if (outField == null || !outField.isJsonPrimitive()) {
            println("RefactorQuery: the query file has no out field");
            return;
        }
        Path out;
        try {
            out = Path.of(outField.getAsString()).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            println("RefactorQuery: the out field is not a path");
            return;
        }
        if (!queryPath.getParent().equals(out.getParent())) {
            println("RefactorQuery: the out file must be in the folder of the query file");
            return;
        }
        if (Files.exists(out, LinkOption.NOFOLLOW_LINKS)) {
            println("RefactorQuery: the out file is there already");
            return;
        }

        try {
            String op = optString(q, "op");
            int limit = optInt(q, "limit", DEFAULT_LIMIT);
            String cursorText = optString(q, "cursor");
            String filter = optText(q, "filter");
            String name = optText(q, "name");
            String address = optText(q, "address");
            int maxChars = optInt(q, "max_chars", DEFAULT_MAX_CHARS);
            if (limit < 1 || limit > MAX_LIMIT) {
                throw new QueryError("bad_query", "limit must be a whole number from 1 to 1000");
            }
            if (maxChars < 1 || maxChars > MAX_MAX_CHARS) {
                throw new QueryError("bad_query",
                    "max_chars must be a whole number from 1 to 200000");
            }
            long cursor = 0;
            if (cursorText != null) {
                if (!cursorText.matches("[0-9]{1,10}")
                    || Long.parseLong(cursorText) > MAX_CURSOR) {
                    throw new QueryError("bad_query",
                        "cursor must be text of digits for a number from 0 to 1000000000");
                }
                cursor = Long.parseLong(cursorText);
            }
            JsonObject resultBody;
            if ("functions".equals(op)) {
                resultBody = listFunctions(filter, cursor, limit);
            } else if ("strings".equals(op)) {
                resultBody = listStrings(filter, cursor, limit);
            } else if ("decompile".equals(op)) {
                resultBody = decompile(name, address, maxChars);
            } else {
                throw new QueryError("bad_query", "unknown op");
            }

            JsonObject program = new JsonObject();
            program.addProperty("name", currentProgram.getName());
            program.addProperty("language", currentProgram.getLanguageID().getIdAsString());
            program.addProperty("compiler",
                currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());

            JsonObject result = new JsonObject();
            result.addProperty("ok", true);
            result.addProperty("op", op);
            result.add("program", program);
            result.addProperty("ghidra_version", Application.getApplicationVersion().toString());
            result.add("result", resultBody);

            writeResult(out, result);
        } catch (QueryError e) {
            writeResult(out, errorResult(e.code, e.getMessage()));
        } catch (Exception e) {
            printTrace(e);
            writeResult(out, errorResult("script_error", e.getClass().getSimpleName()));
        }
    }

    /**
     * Prints the class name and the stack trace elements (class, method and line) of an
     * exception to the Ghidra console. It never prints the message of the exception.
     * @param e the exception
     */
    private void printTrace(Exception e) {
        println("RefactorQuery: script_error " + e.getClass().getName());
        for (StackTraceElement el : e.getStackTrace()) {
            println("RefactorQuery:   at " + el.getClassName() + "." + el.getMethodName()
                + " line " + el.getLineNumber());
        }
    }

    /**
     * Returns every function: first the functions in memory in address order, then the
     * external functions (imports) in address order.
     * @return the list of all functions
     */
    private List<Function> allFunctions() {
        FunctionManager manager = currentProgram.getFunctionManager();
        List<Function> all = new ArrayList<>();
        for (Function f : manager.getFunctions(true)) {
            all.add(f);
        }
        List<Function> external = new ArrayList<>();
        for (Function f : manager.getExternalFunctions()) {
            external.add(f);
        }
        external.sort((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));
        all.addAll(external);
        return all;
    }

    /**
     * Lists the functions in address order, then the external functions, with the filter and
     * paging of the query. The filter looks in the name with its namespace.
     * @param filter text that the name must hold (case ignored), or null
     * @param cursor number of matches to skip
     * @param limit largest number of items
     * @return the result object { items, total, next_cursor }
     */
    private JsonObject listFunctions(String filter, long cursor, int limit) {
        String needle = filter == null ? null : filter.toLowerCase(Locale.ROOT);
        JsonArray items = new JsonArray();
        int total = 0;
        for (Function f : allFunctions()) {
            if (!matches(f.getName(true), needle)) {
                continue;
            }
            if (total >= cursor && items.size() < limit) {
                JsonObject item = new JsonObject();
                addName(item, f);
                item.addProperty("address", f.getEntryPoint().toString());
                item.addProperty("size", f.isExternal() ? 0 : f.getBody().getNumAddresses());
                item.addProperty("external", f.isExternal());
                item.addProperty("thunk", f.isThunk());
                items.add(item);
            }
            total++;
        }
        return pageResult(items, total, cursor);
    }

    /**
     * Lists the defined strings in address order, with the filter and paging of the query.
     * Only top-level data items are read; a data item without a string value is skipped.
     * @param filter text that the string must hold (case ignored), or null
     * @param cursor number of matches to skip
     * @param limit largest number of items
     * @return the result object { items, total, next_cursor }
     */
    private JsonObject listStrings(String filter, long cursor, int limit) {
        String needle = filter == null ? null : filter.toLowerCase(Locale.ROOT);
        JsonArray items = new JsonArray();
        int total = 0;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (!d.hasStringValue()) {
                continue;
            }
            Object value = d.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            String text = (String) value;
            if (!matches(text, needle)) {
                continue;
            }
            if (total >= cursor && items.size() < limit) {
                String shown = cut(text, MAX_STRING_CHARS);
                JsonObject item = new JsonObject();
                item.addProperty("address", d.getAddress().toString());
                item.addProperty("text", shown);
                item.addProperty("truncated", shown.length() < text.length());
                items.add(item);
            }
            total++;
        }
        return pageResult(items, total, cursor);
    }

    /**
     * Decompiles one function, found by its name or by an address inside it. A name matches a
     * function when it is equal to the name with its namespace or to the name without it.
     * @param name function name, or null
     * @param address hex address text, or null
     * @param maxChars largest number of characters of code in the result
     * @return { function, code, truncated, omitted_chars }, or, when several functions have
     *     the name, { candidates, candidates_total, code (null), truncated }
     * @throws QueryError when the function cannot be found or decompiled
     */
    private JsonObject decompile(String name, String address, int maxChars) throws QueryError {
        Function target;
        if (name != null) {
            List<Function> found = new ArrayList<>();
            int count = 0;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName(true).equals(name) || f.getName().equals(name)) {
                    if (found.size() < MAX_CANDIDATES) {
                        found.add(f);
                    }
                    count++;
                }
            }
            if (count == 0) {
                throw new QueryError("function_not_found", "no function with that name");
            }
            if (count > 1) {
                JsonObject res = new JsonObject();
                JsonArray candidates = new JsonArray();
                for (Function f : found) {
                    JsonObject candidate = new JsonObject();
                    addName(candidate, f);
                    candidate.addProperty("address", f.getEntryPoint().toString());
                    candidate.addProperty("thunk", f.isThunk());
                    candidates.add(candidate);
                }
                res.add("candidates", candidates);
                res.addProperty("candidates_total", count);
                res.add("code", JsonNull.INSTANCE);
                res.addProperty("truncated", false);
                return res;
            } else {
                target = found.get(0);
            }
        } else if (address != null) {
            String hex = address;
            if (hex.startsWith("0x") || hex.startsWith("0X")) {
                hex = hex.substring(2);
            }
            Address a = toAddr(hex);
            if (a == null) {
                throw new QueryError("bad_address", "the address cannot be read");
            }
            target = getFunctionContaining(a);
            if (target == null) {
                throw new QueryError("function_not_found", "no function contains that address");
            }
        } else {
            throw new QueryError("bad_query", "decompile needs a name or an address");
        }

        DecompInterface di = new DecompInterface();
        try {
            if (!di.openProgram(currentProgram)) {
                throw new QueryError("decompile_failed",
                    "the decompiler could not open the program");
            }
            DecompileResults r = di.decompileFunction(target, DECOMPILE_TIMEOUT_SECONDS, monitor);
            DecompiledFunction df = r == null || !r.decompileCompleted()
                ? null : r.getDecompiledFunction();
            String code = df == null ? null : df.getC();
            if (code == null) {
                throw new QueryError("decompile_failed", "the decompiler did not finish");
            }
            String shown = cut(code, maxChars);
            JsonObject function = new JsonObject();
            addName(function, target);
            function.addProperty("address", target.getEntryPoint().toString());
            JsonObject result = new JsonObject();
            result.add("function", function);
            result.addProperty("code", shown);
            result.addProperty("truncated", shown.length() < code.length());
            result.addProperty("omitted_chars", code.length() - shown.length());
            return result;
        } finally {
            di.dispose();
        }
    }

    /**
     * Adds the name with its namespace, cut at MAX_NAME_CHARS, and its name_truncated flag.
     * @param obj the object that gets the two members
     * @param f the function
     */
    private static void addName(JsonObject obj, Function f) {
        String full = f.getName(true);
        String shown = cut(full, MAX_NAME_CHARS);
        obj.addProperty("name", shown);
        obj.addProperty("name_truncated", shown.length() < full.length());
    }

    /**
     * Makes the paging result object.
     * @param items the items of this page
     * @param total the number of all matches
     * @param cursor number of matches skipped
     * @return { items, total, next_cursor }
     */
    private static JsonObject pageResult(JsonArray items, int total, long cursor) {
        JsonObject result = new JsonObject();
        result.add("items", items);
        result.addProperty("total", total);
        long end = cursor + items.size();
        if (end < total) {
            result.addProperty("next_cursor", String.valueOf(end));
        } else {
            result.add("next_cursor", JsonNull.INSTANCE);
        }
        return result;
    }

    /**
     * Cuts the text to at most max characters and never leaves half of a surrogate pair.
     * @param text the text to cut
     * @param max largest number of characters (UTF-16 units), 1 or more
     * @return the text, or its start
     */
    private static String cut(String text, int max) {
        if (text.length() <= max) {
            return text;
        }
        int end = max;
        if (Character.isHighSurrogate(text.charAt(end - 1))) {
            end--;
        }
        return text.substring(0, end);
    }

    /**
     * Returns true when the needle is null or the text holds it (case ignored).
     * @param text the text to look in
     * @param needle lower-case filter text, or null
     * @return true for a match
     */
    private static boolean matches(String text, String needle) {
        return needle == null || text.toLowerCase(Locale.ROOT).contains(needle);
    }

    /**
     * Reads a text field of the query.
     * @param q the query
     * @param key the field name
     * @return the text, or null when the field is missing or JSON null
     * @throws QueryError when the field is an object or a list
     */
    private static String optString(JsonObject q, String key) throws QueryError {
        JsonElement e = q.get(key);
        if (e == null || e.isJsonNull()) {
            return null;
        }
        if (!e.isJsonPrimitive()) {
            throw new QueryError("bad_query", key + " must be text");
        }
        return e.getAsString();
    }

    /**
     * Reads a text field of the query that may hold at most MAX_QUERY_TEXT_CHARS characters.
     * @param q the query
     * @param key the field name
     * @return the text, or null when the field is missing or JSON null
     * @throws QueryError when the field is not text or is too long
     */
    private static String optText(JsonObject q, String key) throws QueryError {
        String value = optString(q, key);
        if (value != null && value.length() > MAX_QUERY_TEXT_CHARS) {
            throw new QueryError("bad_query", key + " must be at most 500 characters");
        }
        return value;
    }

    /**
     * Reads a whole-number field of the query: a JSON number or text of 1 to 9 digits.
     * @param q the query
     * @param key the field name
     * @param def the value when the field is missing or JSON null
     * @return the number
     * @throws QueryError when the field is not a whole number of 1 to 9 digits
     */
    private static int optInt(JsonObject q, String key, int def) throws QueryError {
        JsonElement e = q.get(key);
        if (e == null || e.isJsonNull()) {
            return def;
        }
        if (!e.isJsonPrimitive() || !e.getAsString().matches("[0-9]{1,9}")) {
            throw new QueryError("bad_query", key + " must be a whole number");
        }
        return Integer.parseInt(e.getAsString());
    }

    /**
     * Makes the error result { ok: false, error: { code, message } }.
     * @param code machine-readable code
     * @param message plain text
     * @return the error result
     */
    private static JsonObject errorResult(String code, String message) {
        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        JsonObject result = new JsonObject();
        result.addProperty("ok", false);
        result.add("error", error);
        return result;
    }

    /**
     * Writes the result object as JSON text to a new result file. It never replaces a file.
     * Every member is written, also a member that is null.
     * @param out the path of the result file
     * @param result the result object
     * @throws Exception when the file is there already or cannot be written
     */
    private static void writeResult(Path out, JsonObject result) throws Exception {
        String json = new GsonBuilder().disableHtmlEscaping().serializeNulls().create()
            .toJson(result);
        Files.write(out, json.getBytes(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
