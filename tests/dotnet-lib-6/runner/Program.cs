using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace runner
{
    class Program
    {
        static object getObjOrArrayValue(CustomAttributeTypedArgument typedArg)
        {
            if (typedArg.Value != null && typedArg.Value.GetType() == typeof(ReadOnlyCollection<CustomAttributeTypedArgument>))
            {
                var argList = (ReadOnlyCollection<CustomAttributeTypedArgument>)typedArg.Value;
                Type t = typedArg.ArgumentType.GetElementType();
                var ary = Array.CreateInstance(t, argList.Count);

                int i = 0;
                foreach (var myarg in argList)
                {
                    //Console.WriteLine("Add array item {0}", myarg.Value);
                    ary.SetValue(myarg.Value, i++);
                }
                return ary;
            }
            return typedArg.Value;
        }

        static bool RunTestCase(string fullpath, string assemblyName)
        {
            bool hasUnitTest = false;
            bool failed = false;
            Assembly assembly = null;
            try
            {
                assembly = System.Reflection.Assembly.LoadFrom(fullpath);
            }
            catch (Exception ex)
            {
                //Console.WriteLine(e);
                Console.WriteLine("==== Failed to load test {0}", assemblyName);
                return false;
            }

            foreach (Type type in assembly.GetTypes())
            {
                if (type.IsAbstract)
                    continue;

                if (type.GetConstructor(Type.EmptyTypes) == null)
                    continue;

                //Console.WriteLine("Class {0}", type);
                foreach (MethodInfo method in type.GetRuntimeMethods())
                {
                    bool isUnitTest = false;
                    List<IList<CustomAttributeTypedArgument>> theoryArgs = new List<IList<CustomAttributeTypedArgument>>();
                    //Console.WriteLine("    Method: {0}", method.Name);
                    foreach (var attr in method.CustomAttributes)
                    {
                        //Console.WriteLine("        custom attribute: {0} with {1} Constructor Arguments", attr.AttributeType.Name, attr.ConstructorArguments.Count);
                        if (attr.AttributeType.Name == "FactAttribute" || attr.AttributeType.Name == "TheoryAttribute")
                        {
                            isUnitTest = true;
                        }

                        if (attr.AttributeType.Name == "InlineDataAttribute")
                        {
                            theoryArgs.Add(attr.ConstructorArguments);
                        }
                    }

                    if (isUnitTest)
                    {
                        hasUnitTest = true;
                        var obj = Activator.CreateInstance(type);
                        try
                        {
                            if (theoryArgs == null)
                            {
                                //Console.WriteLine("--- Running test " + method.Name + " with no parameters");
                                method.Invoke(obj, null);
                            }
                            else
                            {
                                foreach (var theoryArg in theoryArgs)
                                {
                                    List<object> pprams = new List<object>();
                                    foreach (var onearg in theoryArg)
                                    {
                                        if (onearg.Value != null && onearg.Value.GetType() == typeof(ReadOnlyCollection<CustomAttributeTypedArgument>))
                                        {
                                            var argList = (ReadOnlyCollection<CustomAttributeTypedArgument>)onearg.Value;
                                            foreach (var myarg in argList)
                                            {
                                                //Console.WriteLine("Add parameter in collection {0}", myarg.Value);
                                                object argValue = getObjOrArrayValue(myarg);
                                                pprams.Add(argValue);
                                            }
                                        }
                                        else
                                        {
                                            //Console.WriteLine("Add parameter {0}", onearg.Value);
                                            pprams.Add(onearg.Value);
                                        }
                                    }
                                    string msg = "--- Running test " + method.Name + " with parameters (";
                                    foreach (var o in pprams)
                                    {
                                        msg += (o == null ? "null" : o.ToString()) + " ";
                                    }
                                    //Console.WriteLine(msg + ")");

                                    method.Invoke(obj, pprams.ToArray());
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            //Console.WriteLine("Failure");
                            //Console.WriteLine(e);
                            failed = true;
                        }
                    }
                }
            }
            if (hasUnitTest)
            {
                Console.WriteLine("===== {0}! {1}", failed ? "Failed" : "Passed", assemblyName);
                return !failed;
            }
            else
            {
                Console.WriteLine("!!!!!!! ERROR {0} is NOT an unit test!", assemblyName);
                return false;
            }
        }

        static int Main(string[] args)
        {
            if (args.Length != 2 && args.Length != 1)
            {
                Console.WriteLine("Usage: runner <file-with-list-of-tests> <path-prefix>");
                Console.WriteLine("       runner path-to-test-case");
                return -1;
            }

            bool passed = true;

            if (args.Length == 2)
            {
                var alltests = File.ReadAllLines(args[0]);
                foreach (var fileName in alltests)
                {
                    //Console.WriteLine("name: {0}", assemblyName.Trim());
                    string assemblyName = fileName.Trim();
                    if (assemblyName.StartsWith('#'))
                    {
                        Console.WriteLine("==== Skipping failing test {0}", assemblyName);
                        continue;
                    }

                    string fullpath = args[1] + assemblyName;
                    passed = RunTestCase(fullpath, assemblyName) && passed;
                }
            }
            else if (args.Length == 1)
            {
                var fullpath = args[0];
                var assemblyName = Path.GetFileName(fullpath);
                passed = RunTestCase(fullpath, assemblyName);
            }

            Console.WriteLine("Testing {0}!", passed ? "Complete" : "Failed");
            return passed ? 0 : -1;
        }
    }
}
