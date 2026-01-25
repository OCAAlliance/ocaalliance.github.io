-------------------------------------------------------------------------
CREATING APPNOTE ANnnn
-------------------------------------------------------------------------

	In your application notes working directory:
	............................................

	1.  Compose in Word -> ANnnn.docx .
	
	2.	ANnnn.docx -> (Word save as filtered html) -> ANnnn.htsource .
	
	3.	ANnnn.htsource -> (manual cleanup & apply AN Template) -> ANnnn.htsource .
				AN template is in 'Techsite/appnotes/AN template/Index.htsource' .
	
	4.	ANnnn.htsource  ->(anmake) -> Index.html .
	
-------------------------------------------------------------------------
PUBLISHING ANnnn
-------------------------------------------------------------------------

	In appnotes working directory:
	..............................
	
	5.	Create image JPGs for all figures.
	
	6.	Create images/ and put the images into it.
	
	7.	In Techsite local repo, create directory './appnotes/ANnnn/' .
	
	8.	Copy from appnotes working directory to Techsite './appnotes/ANnnn/:
				Index.html
				images/
				ANnnn.vsdx
				ANnnn.htsource 
				
	9.	Mark working directory folder as EXPORTED.				
				
	In local Techsite './appnotes/ANnnn/:
	.....................................
			
	10.	Open Index.html in MS Edge, make sure it looks OK.
	
	5.	Print the page to 'ANnnn <appnote title).pdf' .
	
	In local Techsite root:
	.................
	
	12.	Update appnotes.html in Techsite local repo root.
	
	13.	Commit & push.
	
-------------------------------------------------------------------------
UPDATING ANnnn
-------------------------------------------------------------------------

	In local Techsite './appnotes/ANnnn/:
	.....................................
	
	1.  Edit ANnnn.htsource. 
			Use steps 1 & 2 if desired, else just edit htsource directly.
			
	2.	Edit images, if necessary.
			Edit ANnnn.vsdx .
			Re-export into images\ .
			
	3.	ANnnn.htsource -> (anmake) -> Index.html .
	
	4.	Open ANnnn/Index.html in MS Edge, make sure it looks OK.
	
	5.	Print the page to Print the page to 'ANnnn <appnote title).pdf' .

	In local Techsite root:
	.................	
	
	6.	Update Date entry in appnotes.html .
	
	4.	Commit & push.
	
-------------------------------------------------------------------------
MACRO PROCESSOR 'PYEXPANDER'
-------------------------------------------------------------------------

Where to get it:

	https://pypi.org/project/pyexpander/
	
Installing pyexpander in Windows (2025.12.19):

	1.	Ensure a Python 3.x version with PIP is installed.
			The one from the Microsoft Store works.
			Some of the ones from the python sites seem to omit PIP.

	2.	Run:  pip3 pyexpander
			This will install expander.exe and msi2pyexpander.exe into an obscure Python directory.
			
	3.	Move expander.exe into an appropriate directory.
			msi2pyexpander.exe isn't useful for our purposes and can be ignored.
		
-------------		
Run cmd (basic - see doc for full details)
	expander.exe [inputfile] >[outputfile]
		where input file contains the macro definitions AND invocations
	