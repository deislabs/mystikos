public class Helloworld {

    public static void main(String[] args) {
        assert args.length == 3;
        assert "red".equals(args[0]);
        assert "green".equals(args[1]);
        assert "blue".equals(args[2]);

        System.out.println("  Hello, World! from Java Application running in Mystikos.");
        System.out.printf("  I received %d args: %s\n", args.length, String.join(", ", args));
        System.out.println("=== passed test (Java Hello World)");
    }
}
