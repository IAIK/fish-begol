#! /bin/octave -qf

function create_plot(prefix, args, data)
  fig = figure;
  plot(1:rows(data), data);
  grid on;
  title(strcat("LowMC Timing n=", args{1}, " k=", args{2}, "\n\n", "Parameters [m]-[r]"));
  xlabel(" ");
  set(gca, 'xtick', 1:rows(data));
  set(gca, 'xticklabel', "");  
  xlim([1, rows(data)])
  for i = 1:rows(data)
    text(i, 0, args{i + 2}, "rotation", 60, "verticalalignment", "top", "horizontalalignment", "right");
  endfor
  ylabel("Time [ms]");
  legend("Instance Gen", "Sign", "Verify");
  print(fig, strcat(prefix, "-", args{1}, "-", args{2}, ".png"), "-dpng");
endfunction

arg_list = argv();

fiatshamir = zeros(nargin - 2, 13);
bellargw   = zeros(nargin - 2, 13);

for i = 3:nargin
  data = csvread(arg_list{i}) / 1000;
  numr = rows(data)/2;
  fiatshamir(i - 2, :) = sum(data(1:numr,:),1)/numr;
  bellargw(i - 2, :) = sum(data(numr+1:rows(data) ,:),1)/numr;
endfor

fs_sum = zeros(nargin - 2, 3);
bg_sum = zeros(nargin - 2, 3);

fs_sum(:,1) = sum(fiatshamir(:,1:3), 2);
bg_sum(:,1) = sum(bellargw(:,1:3), 2);
fs_sum(:,2) = sum(fiatshamir(:,4:8), 2);
bg_sum(:,2) = sum(bellargw(:,4:8), 2);
fs_sum(:,3) = sum(fiatshamir(:,9:13), 2);
bg_sum(:,3) = sum(bellargw(:,9:13), 2);


create_plot("fis", arg_list, fs_sum);
create_plot("bg", arg_list, bg_sum);

