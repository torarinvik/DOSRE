using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DOSRE.Dasm;
using DOSRE.Analysis;
using DOSRE.Renderer.impl;
using Terminal.Gui;

namespace DOSRE.UI.impl
{
    public class InteractiveUI : IUserInterface
    {
        private string _selectedFile;

        private bool _optionAdvancedAnalysis;
        private bool _optionStrings;
        private bool _optionMinimal;
        private string _outputFile;

        private MenuBar _topMenuBar;
        private Window _mainWindow;
        private readonly ProgressBar _progressBar;
        private readonly Label _statusLabel;
        internal InteractiveUI()
        {
            Application.Init();

            //Define Main Window
            _mainWindow = new Window ("DOSRE") {
                X = 0,
                Y = 1,
                Width = Dim.Fill (),
                Height = Dim.Fill ()
            };

            _mainWindow.Add(
                new Label(0, 0, $"--=[About {Constants.ProgramName}]=--"),
                new Label(0, 1, $"{Constants.ProgramName} is an x86 disassembler/decompiler/reconstruction tool for classic DOS/Windows-era binaries"),
                new Label(0, 3, "--=[Credits]=--"),
                new Label(0, 4, "Based on MBBSDASM (c) 2019 Eric Nusbaum, distributed under the 2-clause \"Simplified BSD License\"."),
                new Label(0, 5, "DOSRE fork and enhancements: see LICENSE and git history."),
                new Label(0, 6, "SharpDisam (c) 2015 Justin Stenning (2-clause \"Simplified BSD License\"); Terminal.Gui (c) 2017 Microsoft (MIT)."),
                new Label(0, 8, "--=[Code]=--"),
                new Label(0, 9, $"{Constants.ProgramName} v{Constants.ProgramVersion}")
            );

            _statusLabel = new Label("Ready!")
            {
                X = 1,
                Y = Pos.Percent(80) 
            };
            _mainWindow.Add(_statusLabel);

            _progressBar = new ProgressBar()
            {
                X = 1,
                Y = Pos.Percent(90),
                Width = Dim.Fill(1)
            };
            _mainWindow.Add(_progressBar);

            Application.Top.Add(_mainWindow);

            //Draw Menu Items
            // Creates a menubar, the item "New" has a help menu.
            var menuItems = new List<MenuBarItem>();

            menuItems.Add(
                new MenuBarItem("_File", new MenuItem[]
                {
                    new MenuItem("_Disassemble", "", OpenFile),
                    new MenuItem("_Exit", "", () => { Application.Top.Running = false; })
                }));

            _topMenuBar = new MenuBar(menuItems.ToArray());
            Application.Top.Add(_topMenuBar);

        }

        public void Run()
        {
            //Run it
            Application.Run();
        }

        private void OpenFile()
        {
            //Show Open File Dialog
            var fOpenDialog = new OpenDialog("Open File for Disassembly", "DisassembleSegment File")
            {
                CanChooseFiles = true,
                AllowsMultipleSelection = false,
                CanChooseDirectories = false,
                AllowedFileTypes = new[] {"dll", "exe", "DLL", "EXE"}
            };

            Application.Run(fOpenDialog);

            //Get Selected File
            _selectedFile = fOpenDialog.FilePaths.FirstOrDefault();

            //If nothing is selected, bail
            if (string.IsNullOrEmpty(_selectedFile))
                return;

            _outputFile = $"{_selectedFile.Substring(0, _selectedFile.Length -3)}asm";

            //Show Disassembly Options
            var analysisCheckBox = new CheckBox(20, 0, "Additional analysis") {Checked = true};
            var stringsCheckBox = new CheckBox(20, 1, "Process All Strings") { Checked = true };
            var disassemblyRadioGroup = new RadioGroup(0, 0, new NStack.ustring[] {"_Minimal", "_Normal"}, 1);

            var okBtn = new Button("OK", true);
            okBtn.Clicked += () =>
                {
                    Application.RequestStop();
                    _optionAdvancedAnalysis = analysisCheckBox.Checked;
                    _optionStrings = stringsCheckBox.Checked;
                    _optionMinimal = disassemblyRadioGroup.SelectedItem == 0;
                    Task.Factory.StartNew(() => DoDisassembly());
                };

            var cancelBtn = new Button("Cancel", true);
            cancelBtn.Clicked += () => { Application.RequestStop (); };

            var fv = new FrameView(new Rect(0, 5, 55, 6), "Disassembly Options");
            fv.Add(disassemblyRadioGroup,analysisCheckBox,stringsCheckBox);

            var disOptionsDialog = new Dialog("Disassembly Options", 60, 16, new Button[]{okBtn,cancelBtn});
            disOptionsDialog.Add(
                new Label(0, 0, "Input File:"),
                new TextField(0, 1, 55, _selectedFile),
                new Label(0, 2, "Output File:"),
                new TextField(0, 3, 55, _outputFile),
                fv
            );

            Application.Run(disOptionsDialog);
        }

        private void DoDisassembly()
        {
            using (var dasm = new Disassembler(_selectedFile))
            {
                if (File.Exists(_outputFile))
                    File.Delete(_outputFile);

                _statusLabel.Text = "Performing Disassembly...";
                var inputFile = dasm.Disassemble(_optionMinimal);

                //Apply Selected Analysis
                if (_optionAdvancedAnalysis)
                {
                    _statusLabel.Text = "Performing Additional Analysis...";
                    Analysis.AdvancedAnalysis.Analyze(inputFile);
                }
                _progressBar.Fraction = .25f;


                var _stringRenderer = new StringRenderer(inputFile);

                _statusLabel.Text = "Processing Segment Information...";
                File.AppendAllText(_outputFile, _stringRenderer.RenderSegmentInformation());
                _progressBar.Fraction = .50f;


                _statusLabel.Text = "Processing Entry Table...";
                File.AppendAllText(_outputFile, _stringRenderer.RenderEntryTable());
                _progressBar.Fraction = .75f;

 

                _statusLabel.Text = "Processing Disassembly...";
                File.AppendAllText(_outputFile, _stringRenderer.RenderDisassembly(_optionAdvancedAnalysis));
                _progressBar.Fraction = .85f;


                if (_optionStrings)
                {
                    _statusLabel.Text = "Processing Strings...";
                    File.AppendAllText(_outputFile, _stringRenderer.RenderStrings());
                }

                _statusLabel.Text = "Done!";
                _progressBar.Fraction = 1f;
            }

            var d = new Dialog($"Disassembly Complete!", 50, 12);
            d.Add(new Label(0, 0, $"Output File: {_outputFile}"),
                new Label(0, 1, $"Bytes Written: {new FileInfo(_outputFile).Length}")
            );
            var okBtn = new Button("OK", true);
            okBtn.Clicked += () => { Application.RequestStop (); };
            d.AddButton(okBtn);
            Application.Run(d);
        }
    }
}
